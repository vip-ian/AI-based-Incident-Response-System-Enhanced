"""
Isolation Forest 기반 이상 탐지 시스템
구조화된 로그 데이터에서 이상 패턴을 탐지합니다.
"""
import pandas as pd
import numpy as np
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import datetime
import time
import os

# Elasticsearch 설정
es_hosts = ['localhost:9200']
es_index_name = 'logs'
es_anomaly_index = 'log-anomalies'

# 모델 저장 경로
model_dir = 'models'
model_path = os.path.join(model_dir, 'isolation_forest_model.pkl')

# 디렉토리가 없으면 생성
if not os.path.exists(model_dir):
    os.makedirs(model_dir)

# Elasticsearch 클라이언트 생성
es = Elasticsearch(es_hosts)

class IsolationForestAnomalyDetector:
    def __init__(self, contamination=0.05):
        """
        Isolation Forest 기반 이상 탐지 클래스
        
        Args:
            contamination: 예상되는 이상치의 비율 (0.0 ~ 0.5 사이 값)
        """
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=contamination,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def extract_features(self, logs_df):
        """
        로그 데이터에서 특징(feature)을 추출합니다.
        
        Args:
            logs_df: 로그 데이터가 담긴 DataFrame
            
        Returns:
            특징 벡터가 담긴 DataFrame
        """
        # 로그별 출현 빈도를 계산
        features = {}
        
        # 1. 로그 레벨별 개수
        log_level_counts = logs_df['log_level'].value_counts().to_dict()
        for level, count in log_level_counts.items():
            features[f'log_level_{level}'] = count
        
        # 2. 컴포넌트별 개수
        component_counts = logs_df['component'].value_counts().to_dict()
        for component, count in component_counts.items():
            features[f'component_{component}'] = count
        
        # 3. 시간대별 로그 개수 (시간별)
        logs_df['hour'] = logs_df['timestamp'].apply(
            lambda x: datetime.datetime.strptime(x, '%Y-%m-%d %H:%M:%S').hour
        )
        hour_counts = logs_df['hour'].value_counts().to_dict()
        for hour, count in hour_counts.items():
            features[f'hour_{hour}'] = count
        
        # 4. 에러 관련 키워드 포함 여부
        error_keywords = ['error', 'exception', 'fail', 'failed', 'timeout', 'denied']
        for keyword in error_keywords:
            features[f'keyword_{keyword}'] = logs_df['message'].str.contains(
                keyword, case=False
            ).sum()
        
        # 특징을 DataFrame으로 변환
        features_df = pd.DataFrame([features])
        
        return features_df
    
    def train(self, logs_df):
        """
        로그 데이터로 모델을 학습합니다.
        
        Args:
            logs_df: 로그 데이터가 담긴 DataFrame
            
        Returns:
            학습된 모델
        """
        # 특징 추출
        features_df = self.extract_features(logs_df)
        
        # 특징 정규화
        X = self.scaler.fit_transform(features_df)
        
        # 모델 학습
        self.model.fit(X)
        
        # 학습 완료 상태로 설정
        self.is_trained = True
        
        return self.model
    
    def predict(self, logs_df):
        """
        로그 데이터에서 이상치를 탐지합니다.
        
        Args:
            logs_df: 로그 데이터가 담긴 DataFrame
            
        Returns:
            이상 점수 (낮을수록 이상)와 이상 여부 (1: 정상, -1: 이상)
        """
        if not self.is_trained:
            raise ValueError("모델이 학습되지 않았습니다. 먼저 train 메서드를 호출하세요.")
        
        # 특징 추출
        features_df = self.extract_features(logs_df)
        
        # 특징 정규화
        X = self.scaler.transform(features_df)
        
        # 이상치 점수 계산
        scores = self.model.score_samples(X)
        
        # 이상치 예측 (1: 정상, -1: 이상)
        predictions = self.model.predict(X)
        
        return scores[0], predictions[0]
    
    def save_model(self, path):
        """학습된 모델을 파일로 저장합니다."""
        if not self.is_trained:
            raise ValueError("모델이 학습되지 않았습니다. 먼저 train 메서드를 호출하세요.")
        
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }, path)
        
    def load_model(self, path):
        """저장된 모델을 파일에서 불러옵니다."""
        saved_data = joblib.load(path)
        self.model = saved_data['model']
        self.scaler = saved_data['scaler']
        self.is_trained = saved_data['is_trained']

def fetch_logs_from_elasticsearch(time_window_minutes=30):
    """
    Elasticsearch에서 최근 로그를 가져옵니다.
    
    Args:
        time_window_minutes: 최근 몇 분 동안의 로그를 가져올지 지정
        
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
        "size": 10000  # 최대 10,000개의 로그 가져오기
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
    """모델을 학습하고 저장합니다."""
    # 학습용 로그 데이터 가져오기 (지난 1일 데이터)
    logs_df = fetch_logs_from_elasticsearch(time_window_minutes=1440)
    
    if len(logs_df) == 0:
        print("학습할 로그 데이터가 없습니다.")
        return False
    
    # 모델 생성 및 학습
    detector = IsolationForestAnomalyDetector(contamination=0.05)
    detector.train(logs_df)
    
    # 모델 저장
    detector.save_model(model_path)
    print(f"모델 학습 및 저장 완료: {model_path}")
    
    return True

def detect_anomalies():
    """주기적으로 최근 로그를 분석하여 이상치를 탐지합니다."""
    # 모델 로드
    detector = IsolationForestAnomalyDetector()
    
    try:
        detector.load_model(model_path)
        print(f"모델 로드 완료: {model_path}")
    except (FileNotFoundError, ValueError) as e:
        print(f"저장된 모델을 찾을 수 없습니다. 새로운 모델을 학습합니다. 오류: {e}")
        train_and_save_model()
        detector.load_model(model_path)
    
    # 이상 탐지 루프
    while True:
        try:
            # 최근 로그 데이터 가져오기 (지난 5분 데이터)
            logs_df = fetch_logs_from_elasticsearch(time_window_minutes=5)
            
            if len(logs_df) == 0:
                print("분석할 로그 데이터가 없습니다. 1분 후 다시 시도합니다.")
                time.sleep(60)
                continue
            
            # 이상치 탐지
            score, prediction = detector.predict(logs_df)
            
            # 이상치 탐지 결과 저장
            anomaly_result = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'anomaly_score': float(score),
                'is_anomaly': int(prediction) == -1,
                'log_count': len(logs_df),
                'time_window_minutes': 5,
                'detector_type': 'isolation_forest'
            }
            
            # Elasticsearch에 이상 탐지 결과 저장
            es.index(index=es_anomaly_index, body=anomaly_result)
            
            # 이상치 발견 시 로그
            if int(prediction) == -1:
                print(f"이상치 탐지! 시간: {anomaly_result['timestamp']}, 점수: {score:.4f}")
                # TODO: 알림 시스템 연동 (e.g., Slack, Email)
            
            # 30초 대기 후 다음 분석
            time.sleep(30)
        except Exception as e:
            print(f"이상 탐지 중 오류 발생: {e}")
            time.sleep(60)  # 오류 발생 시 60초 대기 후 재시도

if __name__ == '__main__':
    try:
        print("Isolation Forest 이상 탐지 서비스 시작...")
        # 처음 실행 시 모델 학습
        if not os.path.exists(model_path):
            print("초기 모델 학습 시작...")
            train_and_save_model()
        
        # 이상 탐지 루프 실행
        detect_anomalies()
    except KeyboardInterrupt:
        print("이상 탐지 서비스 종료...")