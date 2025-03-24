"""
로그 수집기 (Kafka 프로듀서)
로그 파일을 모니터링하고 새로운 로그를 Kafka로 전송합니다.
"""
from kafka import KafkaProducer
import json
import time
import os
import glob
from datetime import datetime

# Kafka 설정
bootstrap_servers = ['localhost:9092']
topic_name = 'logs-topic'

# Kafka 프로듀서 생성
producer = KafkaProducer(
    bootstrap_servers=bootstrap_servers,
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
    acks='all',
    retries=3
)

# 로그 디렉토리 설정
log_directory = '/path/to/logs/'
processed_files = set()
current_file = None

def parse_log_line(line):
    """로그 라인을 파싱하여 JSON 형태로 변환합니다."""
    try:
        # 여기서는 예시로 간단한 형식을 가정합니다.
        # 실제 환경에 맞게 로그 파싱 로직을 구현해야 합니다.
        parts = line.strip().split(' ')
        timestamp = parts[0] + ' ' + parts[1]
        log_level = parts[2]
        component = parts[3]
        message = ' '.join(parts[4:])
        
        return {
            'timestamp': timestamp,
            'log_level': log_level,
            'component': component,
            'message': message,
            'raw_log': line.strip(),
            'source_file': os.path.basename(current_file),
            'collected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        # 파싱 실패 시 기본 형식으로 반환
        return {
            'raw_log': line.strip(),
            'source_file': os.path.basename(current_file),
            'collected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'parse_error': str(e)
        }

def send_log_to_kafka(log_data):
    """파싱된 로그 데이터를 Kafka로 전송합니다."""
    future = producer.send(topic_name, log_data)
    try:
        future.get(timeout=10)  # 전송 성공 확인
        return True
    except Exception as e:
        print(f"로그 전송 실패: {e}")
        return False

def process_log_file(file_path):
    """로그 파일을 읽어 각 라인을 Kafka로 전송합니다."""
    global current_file
    current_file = file_path
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if line.strip():  # 빈 라인이 아닐 경우에만 처리
                    log_data = parse_log_line(line)
                    send_log_to_kafka(log_data)
        
        # 처리 완료된 파일 기록
        processed_files.add(file_path)
        print(f"파일 처리 완료: {file_path}")
    except Exception as e:
        print(f"파일 처리 중 오류 발생: {file_path}, 오류: {e}")

def monitor_log_files():
    """로그 디렉토리를 모니터링하여 새로운 로그 파일이나 변경된 파일을 처리합니다."""
    while True:
        # 모든 로그 파일 가져오기
        log_files = glob.glob(os.path.join(log_directory, '*.log'))
        
        for file_path in log_files:
            # 아직 처리하지 않은 파일이거나 이미 처리했지만 수정된 경우
            if file_path not in processed_files:
                process_log_file(file_path)
        
        # 주기적으로 체크 (10초 간격)
        time.sleep(10)

if __name__ == '__main__':
    try:
        print("로그 수집 서비스 시작...")
        monitor_log_files()
    except KeyboardInterrupt:
        print("로그 수집 서비스 종료...")
    finally:
        producer.close()