"""
로그 처리기 (Kafka 컨슈머)
Kafka에서 로그를 가져와 Elasticsearch에 저장합니다.
"""
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
import json
import time
from datetime import datetime

# Kafka 설정
bootstrap_servers = ['localhost:9092']
topic_name = 'logs-topic'
group_id = 'log-processor-group'

# Elasticsearch 설정
es_hosts = ['localhost:9200']
es_index_name = 'logs'

# Kafka 컨슈머 생성
consumer = KafkaConsumer(
    topic_name,
    bootstrap_servers=bootstrap_servers,
    group_id=group_id,
    auto_offset_reset='earliest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
    enable_auto_commit=False
)

# Elasticsearch 클라이언트 생성
es = Elasticsearch(es_hosts)

def create_es_index_if_not_exists():
    """로그 저장을 위한 Elasticsearch 인덱스가 없으면 생성합니다."""
    if not es.indices.exists(index=es_index_name):
        # 인덱스 매핑 설정 (필드 타입 지정)
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
                    "collected_at": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
                    "log_level": {"type": "keyword"},
                    "component": {"type": "keyword"},
                    "message": {"type": "text", "analyzer": "standard"},
                    "raw_log": {"type": "text", "analyzer": "standard"},
                    "source_file": {"type": "keyword"}
                }
            },
            "settings": {
                "number_of_shards": 5,
                "number_of_replicas": 1
            }
        }
        es.indices.create(index=es_index_name, body=mapping)
        print(f"Elasticsearch 인덱스 생성 완료: {es_index_name}")

def store_log_to_elasticsearch(log_data):
    """로그 데이터를 Elasticsearch에 저장합니다."""
    try:
        es.index(index=es_index_name, body=log_data)
        return True
    except Exception as e:
        print(f"Elasticsearch 저장 실패: {e}")
        return False

def process_kafka_messages():
    """Kafka에서 메시지를 가져와 Elasticsearch에 저장합니다."""
    # Elasticsearch 인덱스 확인 및 생성
    create_es_index_if_not_exists()
    
    try:
        # 메시지 처리 루프
        for message in consumer:
            log_data = message.value
            success = store_log_to_elasticsearch(log_data)
            
            if success:
                # 성공적으로 저장되면 오프셋 커밋
                consumer.commit()
            else:
                # 저장 실패 시 잠시 대기 후 재시도
                time.sleep(1)
    except Exception as e:
        print(f"메시지 처리 중 오류 발생: {e}")
    finally:
        consumer.close()

if __name__ == '__main__':
    try:
        print("로그 처리 서비스 시작...")
        process_kafka_messages()
    except KeyboardInterrupt:
        print("로그 처리 서비스 종료...")