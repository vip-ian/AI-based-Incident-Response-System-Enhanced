"""
BERT 기반 비구조화 로그 분석 시스템
로그 메시지의 의미적 패턴을 학습하고 이상을 탐지합니다.
"""
import pandas as pd
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizer, BertModel
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from elasticsearch import Elasticsearch
import datetime
import time
import os
import joblib
import pickle
import json

# CUDA 사용 가능 여부 확인
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {device}")

# Elasticsearch 설정
es_hosts = ['localhost:9200']
es_index_name = 'logs'
es_anomaly_index = 'log-anomalies'

# 모델 저장 경로
model_dir = 'models'
bert_embeddings_path = os.path.join(model_dir, 'bert_embeddings.pkl')
bert_cluster_model_path = os.path.join(model_dir, 'bert_cluster_model.pkl')
bert_metadata_path = os.path.join(model_dir, 'bert_metadata.pkl')

# 디렉토리가 없으면 생성
if not os.path.exists(model_dir):
    os.makedirs(model_dir)

# Elasticsearch 클라이언트 생성
es = Elasticsearch(es_hosts)

class LogDataset(Dataset):
    """로그 데이터셋 클래스"""
    def __init__(self, texts, tokenizer, max_length=128):
        self.texts = texts
        self.tokenizer = tokenizer
        self.max_length = max_length
        
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = self.texts[idx]
        encoding = self.tokenizer(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
            return_token_type_ids=False,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten()
        }

class BERTLogAnalyzer:
    def __init__(self, n_clusters=10, batch_size=32, max_length=128, pretrained_model='bert-base-uncased'):
        """
        BERT 기반 로그 분석 클래스
        
        Args:
            n_clusters: K-means 클러스터링에 사용할 클러스터 수
            batch_size: 배치 크기
            max_length: BERT 입력 최대 길이
            pretrained_model: 사용할 사전 학습된 BERT 모델
        """
        self.n_clusters = n_clusters
        self.batch_size = batch_size
        self.max_length = max_length
        self.pretrained_model = pretrained_model
        
        # BERT 토크나이저와 모델 로드
        self.tokenizer = BertTokenizer.from_pretrained(pretrained_model)
        self.bert_model = BertModel.from_pretrained(pretrained_model)
        self.bert_model = self.bert_model.to(device)
        
        # 클러스터링 모델
        self.kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        self.scaler = StandardScaler()
        
        # 학습 데이터 저장
        self.embeddings = None
        self.cluster_centers = None
        self.cluster_distances = None
        self.is_trained = False
        self.log_messages = None
        
    def extract_features(self, logs_df):
        """로그 메시지에서 BERT 임베딩을 추출"""
        # 로그 메시지 추출
        messages = logs_df['message'].tolist()
        self.log_messages = messages
        
        # 데이터셋 및 데이터로더 생성
        dataset = LogDataset(messages, self.tokenizer, self.max_length)
        dataloader = DataLoader(dataset, batch_size=self.batch_size)
        
        # BERT 모델을 평가 모드로 설정
        self.bert_model.eval()
        
        # 임베딩 추출
        embeddings = []
        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                
                outputs = self.bert_model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
                # [CLS] 토큰의 임베딩 사용 (문장 표현)
                cls_embeddings = outputs.last_hidden_state[:, 0, :]
                embeddings.append(cls_embeddings.cpu().numpy())
        
        # 모든 임베딩 결합
        embeddings = np.vstack(embeddings)
        
        return embeddings
    
    def train(self, logs_df):
        """로그 데이터로 모델을 학습"""
        print("BERT 임베딩 추출 중...")
        embeddings = self.extract_features(logs_df)
        
        # 임베딩 정규화
        print("임베딩 정규화 중...")
        embeddings_scaled = self.scaler.fit_transform(embeddings)
        
        # 최적의 클러스터 수 찾기 (옵션)
        best_n_clusters = self.n_clusters
        best_score = -1
        
        if len(embeddings_scaled) > best_n_clusters * 5:  # 데이터가 충분한 경우에만
            print("최적의 클러스터 수 탐색 중...")
            cluster_range = range(3, min(20, len(embeddings_scaled) // 5))
            for n_clusters in cluster_range:
                kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
                labels = kmeans.fit_predict(embeddings_scaled)
                
                # 실루엣 점수 계산
                score = silhouette_score(embeddings_scaled, labels)
                print(f"  클러스터 수 {n_clusters}: 실루엣 점수 {score:.4f}")
                
                if score > best_score:
                    best_score = score
                    best_n_clusters = n_clusters
            
            print(f"최적의 클러스터 수: {best_n_clusters}")
            self.n_clusters = best_n_clusters
            self.kmeans = KMeans(n_clusters=best_n_clusters, random_state=42)
        
        # K-means 클러스터링 수행
        print("클러스터링 수행 중...")
        self.kmeans.fit(embeddings_scaled)
        
        # 각 클러스터 중심과의 거리 계산
        cluster_labels = self.kmeans.labels_
        cluster_distances = {}
        
        for i in range(self.n_clusters):
            # 클러스터 i에 속하는 샘플 인덱스
            indices = np.where(cluster_labels == i)[0]
            
            if len(indices) > 0:
                # 클러스터 중심과의 거리 계산
                centroid = self.kmeans.cluster_centers_[i]
                distances = np.sqrt(((embeddings_scaled[indices] - centroid) ** 2).sum(axis=1))
                
                # 95 퍼센타일 거리 계산 (이상치 임계값으로 사용)
                threshold = np.percentile(distances, 95)
                
                cluster_distances[i] = {
                    'mean': float(distances.mean()),
                    'std': float(distances.std()),
                    'max': float(distances.max()),
                    'threshold': float(threshold),
                    'sample_count': int(len(indices))
                }
        
        # 학습 데이터 저장
        self.embeddings = embeddings
        self.cluster_distances = cluster_distances
        self.is_trained = True
        
        return self.kmeans
    
    def predict(self, logs_df):
        """새로운 로그 데이터에서 이상치 탐지"""
        if not self.is_trained:
            raise ValueError("모델이 학습되지 않았습니다. 먼저 train 메서드를 호출하세요.")
        
        # BERT 임베딩 추출
        embeddings = self.extract_features(logs_df)
        
        # 임베딩 정규화
        embeddings_scaled = self.scaler.transform(embeddings)
        
        # 클러스터 할당 및 거리 계산
        cluster_labels = self.kmeans.predict(embeddings_scaled)
        distances = []
        anomalies = []
        
        for i, (label, embedding) in enumerate(zip(cluster_labels, embeddings_scaled)):
            # 할당된 클러스터 중심과의 거리 계산
            centroid = self.kmeans.cluster_centers_[label]
            distance = np.sqrt(((embedding - centroid) ** 2).sum())
            distances.append(distance)
            
            # 이상치 여부 판단
            threshold = self.cluster_distances[label]['threshold']
            is_anomaly = distance > threshold
            anomalies.append(is_anomaly)
            
            if is_anomaly:
                print(f"이상 로그 탐지: 클러스터 {label}, 거리 {distance:.4f}, 임계값 {threshold:.4f}")
                print(f"로그 메시지: {logs_df['message'].iloc[i][:100]}...")
        
        return np.array(distances), np.array(anomalies), cluster_labels
    
    def save_model(self):
        """모델 저장"""
        if not self.is_trained:
            raise ValueError("모델이 학습되지 않았습니다. 먼저 train 메서드를 호출하세요.")
        
        # K-means 모델 저장
        joblib.dump(self.kmeans, bert_cluster_model_path)
        
        # 스케일러 저장
        metadata = {
            'scaler': self.scaler,
            'cluster_distances': self.cluster_distances,
            'n_clusters': self.n_clusters,
            'is_trained': self.is_trained
        }
        joblib.dump(metadata, bert_metadata_path)
        
        print(f"모델 저장 완료: {bert_cluster_model_path}, {bert_metadata_path}")
    
    def load_model(self):
        """저장된 모델 로드"""
        # K-means 모델 로드
        self.kmeans = joblib.load(bert_cluster_model_path)
        
        # 메타데이터 로드
        metadata = joblib.load(bert_metadata_path)
        self.scaler = metadata['scaler']
        self.cluster_distances = metadata['cluster_distances']
        self.n_clusters = metadata['n_clusters']
        self.is_trained = metadata['is_trained']
        
        print(f"모델 로드 완료: {bert_cluster_model_path}, {bert_metadata_path}")

def fetch_logs_from_elasticsearch(time_window_minutes=30, size=5000):
    """
    Elasticsearch에서 최근 로그를 가져옵니다.
    
    Args:
        time_window_minutes: 최근 몇 분 동안의 로그를 가져올지 지정
        size: 가져올 로그 최대 개수
        
    Returns:
        로그 데이터가 담긴 DataFrame
    """
    # 현재 시간 기준으로 검색 범위 설정
    now = datetime.datetime.now()
    time_from = now - datetime.timedelta(minutes=time_window_minutes)
    
    # Elasticsearch 쿼리 작성
    query = {
        "query": {
            "range": {
                "collected_at": {
                    "gte": time_from.strftime('%Y-%m-%d %H:%M:%S'),
                    "lte": now.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
        },
        "size": size  
    }
    
    # 쿼리 실행
    response = es.search(index=es_index_name, body=query)
    
    # 결과를 DataFrame으로 변환
    logs = []
    for hit in response['hits']['hits']:
        log_data = hit['_source']
        logs.append(log_data)
    
    logs_df = pd.DataFrame(logs)
    
    return logs_df

def train_and_save_model():
    """BERT 모델을 학습하고 저장합니다."""
    # 학습용 로그 데이터 가져오기 (최근 1일 데이터, 최대 10,000개)
    logs_df = fetch_logs_from_elasticsearch(time_window_minutes=1440, size=10000)
    
    if len(logs_df) == 0:
        print("학습할 로그 데이터가 없습니다.")
        return False
    
    if 'message' not in logs_df.columns:
        print("로그 데이터에 message 필드가 없습니다.")
        return False
    
    # 중복 로그 메시지 제거
    logs_df = logs_df.drop_duplicates(subset=['message'])
    print(f"학습에 사용할 고유 로그 메시지 수: {len(logs_df)}")
    
    # 모델 생성 및 학습
    analyzer = BERTLogAnalyzer(n_clusters=10, batch_size=32)
    
    try:
        analyzer.train(logs_df)
        analyzer.save_model()
        print("모델 학습 및 저장 완료")
        return True
    except Exception as e:
        print(f"모델 학습 중 오류 발생: {e}")
        return False

def detect_anomalies():
    """주기적으로 최근 로그를 분석하여 이상치를 탐지합니다."""
    # 모델 로드
    analyzer = BERTLogAnalyzer()
    
    try:
        analyzer.load_model()
    except (FileNotFoundError, ValueError) as e:
        print(f"저장된 모델을 찾을 수 없습니다. 새로운 모델을 학습합니다. 오류: {e}")
        train_and_save_model()
        analyzer.load_model()
    
    # 이상 탐지 루프
    while True:
        try:
            # 최근 로그 데이터 가져오기 (지난 10분 데이터)
            logs_df = fetch_logs_from_elasticsearch(time_window_minutes=10, size=1000)
            
            if len(logs_df) == 0:
                print("분석할 로그 데이터가 없습니다. 1분 후 다시 시도합니다.")
                time.sleep(60)
                continue
            
            if 'message' not in logs_df.columns:
                print("로그 데이터에 message 필드가 없습니다. 1분 후 다시 시도합니다.")
                time.sleep(60)
                continue
            
            # 중복 로그 메시지 제거
            logs_df = logs_df.drop_duplicates(subset=['message'])
            print(f"분석할 고유 로그 메시지 수: {len(logs_df)}")
            
            if len(logs_df) == 0:
                print("분석할 고유 로그 메시지가 없습니다. 1분 후 다시 시도합니다.")
                time.sleep(60)
                continue
            
            # 이상치 탐지
            distances, anomalies, cluster_labels = analyzer.predict(logs_df)
            
            # 이상치가 하나라도 발견되었는지 확인
            any_anomaly = np.any(anomalies)
            
            # 클러스터별 통계
            cluster_stats = {}
            for i in range(analyzer.n_clusters):
                cluster_indices = np.where(cluster_labels == i)[0]
                if len(cluster_indices) > 0:
                    anomaly_indices = np.where(anomalies & (cluster_labels == i))[0]
                    cluster_stats[str(i)] = {
                        'count': int(len(cluster_indices)),
                        'anomaly_count': int(len(anomaly_indices)),
                        'anomaly_ratio': float(len(anomaly_indices) / len(cluster_indices))
                    }
            
            # 이상치 탐지 결과 저장
            anomaly_result = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'max_distance': float(np.max(distances)) if len(distances) > 0 else 0,
                'mean_distance': float(np.mean(distances)) if len(distances) > 0 else 0,
                'is_anomaly': bool(any_anomaly),
                'anomaly_count': int(np.sum(anomalies)),
                'total_logs': len(logs_df),
                'time_window_minutes': 10,
                'detector_type': 'bert',
                'cluster_stats': cluster_stats
            }
            
            # Elasticsearch에 이상 탐지 결과 저장
            es.index(index=es_anomaly_index, body=anomaly_result)
            
            # 이상치 발견 시 로그
            if any_anomaly:
                print(f"이상치 탐지! 시간: {anomaly_result['timestamp']}, "
                      f"이상 로그: {anomaly_result['anomaly_count']}/{anomaly_result['total_logs']}")
                
                # 이상 로그 샘플 출력 (최대 5개)
                anomaly_indices = np.where(anomalies)[0]
                sample_size = min(5, len(anomaly_indices))
                sample_indices = np.random.choice(anomaly_indices, sample_size, replace=False)
                print("\n이상 로그 샘플:")
                for idx in sample_indices:
                    print(f"- 클러스터 {cluster_labels[idx]}, 거리 {distances[idx]:.4f}: {logs_df['message'].iloc[idx][:100]}...")
                
                # TODO: 알림 시스템 연동 (e.g., Slack, Email)
            
            # 2분 대기 후 다음 분석 (BERT는 계산이 많이 필요하므로 더 긴 간격 사용)
            time.sleep(120)
        except Exception as e:
            print(f"이상 탐지 중 오류 발생: {e}")
            time.sleep(120)  # 오류 발생 시 2분 대기 후 재시도

if __name__ == '__main__':
    try:
        print("BERT 로그 분석 서비스 시작...")
        # 처음 실행 시 모델 학습
        if not (os.path.exists(bert_cluster_model_path) and os.path.exists(bert_metadata_path)):
            print("초기 모델 학습 시작...")
            train_and_save_model()
        
        # 이상 탐지 루프 실행
        detect_anomalies()
    except KeyboardInterrupt:
        print("로그 분석 서비스 종료...")