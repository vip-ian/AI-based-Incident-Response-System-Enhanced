"""
PyTorch LSTM 기반 시퀀스 이상 탐지 시스템
로그 시퀀스 패턴을 학습하고 비정상적인 로그 패턴을 탐지합니다.
"""
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import MinMaxScaler
from elasticsearch import Elasticsearch
import datetime
import time
import os
import joblib
import json
import logging
import threading  # threading 모듈 추가

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("lstm_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("lstm_detector")

# 경고 메시지 숨기기
os.environ['PYTHONWARNINGS'] = 'ignore::UserWarning'

# Elasticsearch 설정
es_hosts = ['localhost:9200']
es_index_name = 'logs'
es_anomaly_index = 'log-anomalies'

# 모델 저장 경로
model_dir = 'models'
lstm_model_path = os.path.join(model_dir, 'lstm_model.pth')
lstm_scaler_path = os.path.join(model_dir, 'lstm_scaler.pkl')
lstm_metadata_path = os.path.join(model_dir, 'lstm_metadata.pkl')

# 디렉토리가 없으면 생성
if not os.path.exists(model_dir):
    os.makedirs(model_dir)

# Elasticsearch 클라이언트 생성
es = Elasticsearch(es_hosts)

# 시퀀스 데이터셋 클래스
class LogSequenceDataset(Dataset):
    def __init__(self, sequences, targets):
        self.sequences = sequences
        self.targets = targets
        
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        return (
            torch.FloatTensor(self.sequences[idx]),
            torch.FloatTensor(self.targets[idx])
        )

# LSTM 모델 정의
class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, dropout=0.2):
        super(LSTMModel, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_dim, 
            hidden_dim, 
            num_layers=num_layers, 
            batch_first=True, 
            dropout=dropout
        )
        
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_dim, input_dim)
        
    def forward(self, x):
        # LSTM 출력, 히든 스테이트
        lstm_out, _ = self.lstm(x)
        
        # 드롭아웃 적용
        out = self.dropout(lstm_out[:, -1, :])
        
        # 전결합층
        out = self.fc(out)
        
        return out

class LSTMAnomalyDetector:
    def __init__(self, seq_length=10, threshold=None, device=None):
        """
        LSTM 기반 시퀀스 이상 탐지 클래스
        
        Args:
            seq_length: 시퀀스 길이 (이전 몇 개의 로그를 기반으로 예측할지)
            threshold: 이상치 판단 임계값 (None이면 학습 데이터의 95 퍼센타일 사용)
            device: 학습 및 추론에 사용할 장치 (None이면 자동 감지)
        """
        self.seq_length = seq_length
        self.threshold = threshold
        self.scaler = MinMaxScaler(feature_range=(0, 1))
        self.model = None
        self.features = None
        self.feature_columns = None
        self.is_trained = False
        
        # 장치 설정 (GPU가 있으면 사용, 없으면 CPU)
        self.device = device if device else ('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Using device: {self.device}")
    
    def create_sequences(self, data):
        """입력 데이터를 시퀀스로 변환"""
        xs, ys = [], []
        for i in range(len(data) - self.seq_length):
            x = data[i:i + self.seq_length]
            y = data[i + self.seq_length]
            xs.append(x)
            ys.append(y)
        return np.array(xs), np.array(ys)
    
    def preprocess_data(self, logs_df):
        """로그 데이터를 전처리하여 특징을 추출"""
        # 1. 시간별로 집계
        logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
        logs_df.set_index('timestamp', inplace=True)
        
        # 2. 각 분마다 로그 레벨별 개수 집계
        logs_df['minute'] = logs_df.index.floor('min')
        
        # 피벗 테이블 생성 (분 단위로 로그 레벨 개수 집계)
        level_counts = logs_df.pivot_table(
            index='minute',
            columns='log_level',
            aggfunc='size',
            fill_value=0
        ).reset_index()
        
        # 에러 키워드 포함 여부 집계
        error_keywords = ['error', 'exception', 'fail', 'failed', 'timeout', 'denied']
        for keyword in error_keywords:
            keyword_df = logs_df[logs_df['message'].str.contains(keyword, case=False, na=False)]
            keyword_counts = keyword_df.groupby('minute').size().reset_index(name=f'keyword_{keyword}')
            level_counts = pd.merge(level_counts, keyword_counts, on='minute', how='left')
            level_counts[f'keyword_{keyword}'].fillna(0, inplace=True)
        
        # 컴포넌트별 개수 집계
        for component in logs_df['component'].unique():
            comp_df = logs_df[logs_df['component'] == component]
            comp_counts = comp_df.groupby('minute').size().reset_index(name=f'component_{component}')
            level_counts = pd.merge(level_counts, comp_counts, on='minute', how='left')
            level_counts[f'component_{component}'].fillna(0, inplace=True)
        
        # 'minute' 열을 인덱스로 설정하고 제거
        level_counts.set_index('minute', inplace=True)
        
        return level_counts
    
    def train(self, logs_df, epochs=50, batch_size=32, validation_split=0.2, learning_rate=0.001):
        """LSTM 모델 학습"""
        # 데이터 전처리
        self.features = self.preprocess_data(logs_df)
        self.feature_columns = self.features.columns
        
        # 데이터 정규화
        scaled_data = self.scaler.fit_transform(self.features)
        
        # 시퀀스 생성
        X, y = self.create_sequences(scaled_data)
        
        if len(X) == 0:
            raise ValueError("시퀀스를 생성할 데이터가 충분하지 않습니다.")
        
        # 학습/검증 데이터 분할
        split_idx = int(len(X) * (1 - validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]
        
        # 데이터셋 및 데이터로더 생성
        train_dataset = LogSequenceDataset(X_train, y_train)
        val_dataset = LogSequenceDataset(X_val, y_val)
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size)
        
        # 모델 생성
        input_dim = self.features.shape[1]
        self.model = LSTMModel(input_dim=input_dim)
        self.model.to(self.device)
        
        # 손실 함수와 옵티마이저 설정
        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        
        # 학습 루프
        best_val_loss = float('inf')
        patience = 5  # Early stopping patience
        patience_counter = 0
        
        logger.info(f"Starting training with {len(X_train)} sequences for {epochs} epochs")
        for epoch in range(epochs):
            # 학습 모드
            self.model.train()
            train_loss = 0.0
            
            for inputs, targets in train_loader:
                inputs, targets = inputs.to(self.device), targets.to(self.device)
                
                # 그래디언트 초기화
                optimizer.zero_grad()
                
                # 순전파
                outputs = self.model(inputs)
                
                # 손실 계산
                loss = criterion(outputs, targets)
                
                # 역전파 및 최적화
                loss.backward()
                optimizer.step()
                
                train_loss += loss.item() * inputs.size(0)
            
            train_loss /= len(train_dataset)
            
            # 검증 모드
            self.model.eval()
            val_loss = 0.0
            
            with torch.no_grad():
                for inputs, targets in val_loader:
                    inputs, targets = inputs.to(self.device), targets.to(self.device)
                    outputs = self.model(inputs)
                    loss = criterion(outputs, targets)
                    val_loss += loss.item() * inputs.size(0)
            
            val_loss /= len(val_dataset)
            
            # 로깅
            logger.info(f"Epoch {epoch+1}/{epochs} - Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}")
            
            # 조기 종료 로직
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                
                # 최고 성능 모델 저장
                torch.save(self.model.state_dict(), lstm_model_path)
                logger.info(f"Model improved, saved to {lstm_model_path}")
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    logger.info(f"Early stopping at epoch {epoch+1}")
                    break
        
        # 저장된 최고 성능 모델 로드
        self.model.load_state_dict(torch.load(lstm_model_path))
        
        # 임계값 계산 (학습 데이터의 95 퍼센타일)
        if self.threshold is None:
            self.model.eval()
            predictions = []
            errors = []
            
            with torch.no_grad():
                for i in range(len(X)):
                    x = torch.FloatTensor(X[i]).unsqueeze(0).to(self.device)
                    actual = y[i]
                    predicted = self.model(x).cpu().numpy()[0]
                    predictions.append(predicted)
                    error = np.mean(np.abs(predicted - actual))
                    errors.append(error)
            
            self.threshold = np.percentile(errors, 95)
            logger.info(f"임계값 설정: {self.threshold}")
        
        self.is_trained = True
        return train_loss, val_loss
    
    def predict(self, logs_df):
        """새로운 데이터에 대한 이상 탐지"""
        if not self.is_trained:
            raise ValueError("모델이 학습되지 않았습니다. 먼저 train 메서드를 호출하세요.")
        
        # 데이터 전처리
        features = self.preprocess_data(logs_df)
        
        # 특징 열이 학습 데이터와 일치하는지 확인하고 조정
        for col in self.feature_columns:
            if col not in features.columns:
                features[col] = 0
        
        features = features[self.feature_columns]
        
        # 데이터 정규화
        scaled_data = self.scaler.transform(features)
        
        # 시퀀스 생성
        X, y = self.create_sequences(scaled_data)
        
        if len(X) == 0:
            # 시퀀스를 만들 수 있는 충분한 데이터가 없는 경우
            logger.warning("충분한 시퀀스 데이터가 없습니다.")
            return None, None
        
        # 모델을 평가 모드로 설정
        self.model.eval()
        
        # 예측 및 오차 계산
        predictions = []
        errors = []
        
        with torch.no_grad():
            for i in range(len(X)):
                x = torch.FloatTensor(X[i]).unsqueeze(0).to(self.device)
                actual = y[i]
                predicted = self.model(x).cpu().numpy()[0]
                predictions.append(predicted)
                error = np.mean(np.abs(predicted - actual))
                errors.append(error)
        
        # 이상치 판단
        anomalies = np.array(errors) > self.threshold
        
        return np.array(errors), anomalies
    
    def save_model(self):
        """모델 저장"""
        if not self.is_trained:
            raise ValueError("모델이 학습되지 않았습니다. 먼저 train 메서드를 호출하세요.")
        
        # 모델 가중치는 이미 학습 중에 저장됨
        
        # 스케일러와 메타데이터 저장
        joblib.dump(self.scaler, lstm_scaler_path)
        
        # 메타데이터 저장
        metadata = {
            'seq_length': self.seq_length,
            'threshold': self.threshold,
            'feature_columns': list(self.feature_columns),
            'is_trained': self.is_trained
        }
        joblib.dump(metadata, lstm_metadata_path)
        
        logger.info(f"모델 저장 완료: {lstm_model_path}, {lstm_scaler_path}, {lstm_metadata_path}")
    
    def load_model(self):
        """저장된 모델 로드"""
        # 모델 가중치 로드
        input_dim = len(joblib.load(lstm_metadata_path)['feature_columns'])
        self.model = LSTMModel(input_dim=input_dim)
        self.model.load_state_dict(torch.load(lstm_model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        
        # 스케일러 로드
        self.scaler = joblib.load(lstm_scaler_path)
        
        # 메타데이터 로드
        metadata = joblib.load(lstm_metadata_path)
        self.seq_length = metadata['seq_length']
        self.threshold = metadata['threshold']
        self.feature_columns = metadata['feature_columns']
        self.is_trained = metadata['is_trained']
        
        logger.info(f"모델 로드 완료: {lstm_model_path}")

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
    try:
        response = es.search(index=es_index_name, body=query)
        
        # 결과를 DataFrame으로 변환
        logs = []
        for hit in response['hits']['hits']:
            log_data = hit['_source']
            logs.append(log_data)
        
        logs_df = pd.DataFrame(logs)
        logger.info(f"Elasticsearch에서 {len(logs_df)}개의 로그 메시지를 가져왔습니다.")
        return logs_df
    except Exception as e:
        logger.error(f"Elasticsearch 쿼리 중 오류 발생: {e}")
        return pd.DataFrame()

def train_and_save_model():
    """LSTM 모델을 학습하고 저장합니다."""
    # 학습용 로그 데이터 가져오기 (지난 1일 데이터)
    logs_df = fetch_logs_from_elasticsearch(time_window_minutes=1440)
    
    if len(logs_df) == 0:
        logger.error("학습할 로그 데이터가 없습니다.")
        return False
    
    if 'timestamp' not in logs_df.columns:
        logger.error("로그 데이터에 timestamp 필드가 없습니다.")
        return False
    
    # 중복 로그 메시지 제거 (선택 사항)
    logs_df.drop_duplicates(subset=['message', 'timestamp'], keep='first', inplace=True)
    
    # 모델 생성 및 학습
    detector = LSTMAnomalyDetector(seq_length=10)
    
    try:
        train_loss, val_loss = detector.train(
            logs_df, 
            epochs=30, 
            batch_size=32, 
            validation_split=0.2,
            learning_rate=0.001
        )
        detector.save_model()
        logger.info(f"모델 학습 완료: 최종 학습 손실 {train_loss:.4f}, 검증 손실 {val_loss:.4f}")
        return True
    except Exception as e:
        logger.error(f"모델 학습 중 오류 발생: {e}")
        return False

def detect_anomalies():
    """주기적으로 최근 로그를 분석하여 이상치를 탐지합니다."""
    # 모델 로드
    detector = LSTMAnomalyDetector()
    
    try:
        detector.load_model()
    except (FileNotFoundError, ValueError) as e:
        logger.warning(f"저장된 모델을 찾을 수 없습니다. 새로운 모델을 학습합니다. 오류: {e}")
        train_and_save_model()
        detector.load_model()
    
    # 이상 탐지 루프
    while True:
        try:
            # 최근 로그 데이터 가져오기 (지난 30분 데이터)
            # LSTM은 시퀀스 데이터가 필요하므로 더 긴 시간 범위 사용
            logs_df = fetch_logs_from_elasticsearch(time_window_minutes=30)
            
            if len(logs_df) == 0:
                logger.warning("분석할 로그 데이터가 없습니다. 1분 후 다시 시도합니다.")
                time.sleep(60)
                continue
            
            if 'timestamp' not in logs_df.columns:
                logger.warning("로그 데이터에 timestamp 필드가 없습니다. 1분 후 다시 시도합니다.")
                time.sleep(60)
                continue
            
            # 이상치 탐지
            errors, anomalies = detector.predict(logs_df)
            
            if errors is None or anomalies is None:
                logger.warning("충분한 시퀀스 데이터가 없습니다. 1분 후 다시 시도합니다.")
                time.sleep(60)
                continue
            
            # 이상치가 하나라도 발견되었는지 확인
            any_anomaly = np.any(anomalies)
            
            # 이상치 탐지 결과 저장
            anomaly_result = {
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'max_error': float(np.max(errors)),
                'mean_error': float(np.mean(errors)),
                'is_anomaly': bool(any_anomaly),
                'anomaly_count': int(np.sum(anomalies)),
                'total_sequences': len(anomalies),
                'log_count': len(logs_df),
                'time_window_minutes': 30,
                'detector_type': 'lstm',
                'threshold': float(detector.threshold)
            }
            
            # Elasticsearch에 이상 탐지 결과 저장
            es.index(index=es_anomaly_index, body=anomaly_result)
            
            # 이상치 발견 시 로그
            if any_anomaly:
                logger.warning(
                    f"이상치 탐지! 시간: {anomaly_result['timestamp']}, "
                    f"평균 오차: {anomaly_result['mean_error']:.4f}, "
                    f"이상 시퀀스: {anomaly_result['anomaly_count']}/{anomaly_result['total_sequences']}"
                )
                
                # 이상 시퀀스 샘플 로깅
                anomaly_indices = np.where(anomalies)[0]
                sample_size = min(3, len(anomaly_indices))
                sample_indices = np.random.choice(anomaly_indices, sample_size, replace=False)
                
                for idx in sample_indices:
                    logger.info(f"이상 시퀀스 #{idx}: 오차 {errors[idx]:.4f} (임계값: {detector.threshold:.4f})")
            else:
                logger.info(
                    f"정상 상태: {anomaly_result['timestamp']}, "
                    f"평균 오차: {anomaly_result['mean_error']:.4f}, "
                    f"총 시퀀스: {anomaly_result['total_sequences']}"
                )
            
            # 30초 대기 후 다음 분석
            time.sleep(30)
        except Exception as e:
            logger.error(f"이상 탐지 중 오류 발생: {e}")
            time.sleep(60)  # 오류 발생 시 60초 대기 후 재시도

def periodically_retrain_model(interval_hours=24):
    """주기적으로 모델을 재학습합니다."""
    while True:
        try:
            # 모델 재학습
            logger.info(f"주기적 모델 재학습 시작 (간격: {interval_hours}시간)")
            train_and_save_model()
            
            # 다음 학습까지 대기
            time.sleep(interval_hours * 3600)
        except Exception as e:
            logger.error(f"모델 재학습 중 오류 발생: {e}")
            time.sleep(3600)  # 오류 발생 시 1시간 대기 후 재시도

if __name__ == '__main__':
    try:
        logger.info("LSTM 이상 탐지 서비스 시작...")
        
        # 별도 스레드에서 주기적 재학습 실행
        retraining_thread = threading.Thread(
            target=periodically_retrain_model,
            daemon=True
        )
        retraining_thread.start()
        
        # 처음 실행 시 모델 학습
        if not os.path.exists(lstm_model_path):
            logger.info("초기 모델 학습 시작...")
            train_and_save_model()
        
        # 이상 탐지 루프 실행
        detect_anomalies()
    except KeyboardInterrupt:
        logger.info("이상 탐지 서비스 종료...")