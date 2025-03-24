"""
SOAR 통합 모듈 (Part 1)
이상 탐지 결과를 SOAR 플랫폼(Shuffle)과 연동하여 자동화된 대응을 수행합니다.
"""
import requests
import json
import time
import datetime
import logging
import os
import hashlib
from elasticsearch import Elasticsearch

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("soar_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("soar_integration")

# Elasticsearch 설정
es_hosts = ['localhost:9200']
es_anomaly_index = 'log-anomalies'
es_logs_index = 'logs'
es_incident_index = 'security-incidents'

# SOAR(Shuffle) 설정
SHUFFLE_API_URL = os.environ.get('SHUFFLE_API_URL', 'http://localhost:3001/api/v1')
SHUFFLE_API_KEY = os.environ.get('SHUFFLE_API_KEY', 'YOUR_SHUFFLE_API_KEY')
SHUFFLE_WORKFLOW_ID = os.environ.get('SHUFFLE_WORKFLOW_ID', 'YOUR_WORKFLOW_ID')

# Elasticsearch 클라이언트 생성
es = Elasticsearch(es_hosts)

# 처리된 인시던트 기록 (중복 방지)
processed_incidents = set()

class Incident:
    """인시던트 정보를 저장하는 클래스"""
    def __init__(self, 
                 anomaly_data, 
                 incident_id=None, 
                 status="new", 
                 severity="medium", 
                 title=None, 
                 description=None):
        
        self.anomaly_data = anomaly_data
        self.timestamp = anomaly_data.get('timestamp', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.detector_type = anomaly_data.get('detector_type', 'unknown')
        
        # ID 생성 (없으면 자동 생성)
        if incident_id:
            self.incident_id = incident_id
        else:
            # 타임스탬프와 탐지기 유형으로 고유 ID 생성
            hash_input = f"{self.timestamp}_{self.detector_type}_{json.dumps(anomaly_data)}"
            self.incident_id = hashlib.md5(hash_input.encode()).hexdigest()
        
        self.status = status
        self.severity = severity
        
        # 제목 설정 (없으면 자동 생성)
        if title:
            self.title = title
        else:
            detector_map = {
                'isolation_forest': '구조화 데이터 분석',
                'lstm': '시퀀스 패턴 분석',
                'bert': '로그 메시지 의미 분석'
            }
            detector_name = detector_map.get(self.detector_type, self.detector_type)
            self.title = f"{detector_name}에서 발견된 로그 이상 패턴"
        
        # 설명 설정 (없으면 자동 생성)
        if description:
            self.description = description
        else:
            self.description = self._generate_description()
        
        # 대응 조치 정보
        self.actions = []
        self.created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.updated_at = self.created_at
    
    def _generate_description(self):
        """이상 탐지 데이터를 기반으로 인시던트 설명 생성"""
        detector_type = self.detector_type
        
        description = f"탐지 시간: {self.timestamp}\n"
        description += f"탐지기 유형: {detector_type}\n\n"
        
        if detector_type == 'isolation_forest':
            description += f"이상 점수: {self.anomaly_data.get('anomaly_score', 0):.4f}\n"
            description += f"분석된 로그 수: {self.anomaly_data.get('log_count', 0)}\n"
            description += f"시간 범위: {self.anomaly_data.get('time_window_minutes', 0)}분\n"
        
        elif detector_type == 'lstm':
            description += f"평균 오차: {self.anomaly_data.get('mean_error', 0):.4f}\n"
            description += f"최대 오차: {self.anomaly_data.get('max_error', 0):.4f}\n"
            description += f"이상 시퀀스: {self.anomaly_data.get('anomaly_count', 0)}/{self.anomaly_data.get('total_sequences', 0)}\n"
            description += f"시간 범위: {self.anomaly_data.get('time_window_minutes', 0)}분\n"
        
        elif detector_type == 'bert':
            description += f"평균 거리: {self.anomaly_data.get('mean_distance', 0):.4f}\n"
            description += f"최대 거리: {self.anomaly_data.get('max_distance', 0):.4f}\n"
            description += f"이상 로그: {self.anomaly_data.get('anomaly_count', 0)}/{self.anomaly_data.get('total_logs', 0)}\n"
            description += f"시간 범위: {self.anomaly_data.get('time_window_minutes', 0)}분\n"
        
        return description
    
    def to_dict(self):
        """인시던트 객체를 딕셔너리로 변환"""
        return {
            'incident_id': self.incident_id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'severity': self.severity,
            'detector_type': self.detector_type,
            'anomaly_data': self.anomaly_data,
            'actions': self.actions,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'timestamp': self.timestamp
        }
    
    def add_action(self, action_type, description, status="completed", timestamp=None):
        """인시던트에 대응 조치 추가"""
        if timestamp is None:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        action = {
            'action_type': action_type,
            'description': description,
            'status': status,
            'timestamp': timestamp
        }
        
        self.actions.append(action)
        self.updated_at = timestamp
        return action
    
    def update_status(self, status, reason=None):
        """인시던트 상태 업데이트"""
        self.status = status
        self.updated_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        action_description = f"인시던트 상태가 '{status}'(으)로 변경되었습니다."
        if reason:
            action_description += f" 사유: {reason}"
        
        self.add_action("status_change", action_description)
        """
SOAR 통합 모듈 (Part 2)
이상 탐지 결과를 SOAR 플랫폼(Shuffle)과 연동하여 자동화된 대응을 수행합니다.
"""

def fetch_recent_anomalies(minutes=5):
    """
    Elasticsearch에서 최근 이상 탐지 결과를 가져옵니다.
    
    Args:
        minutes: 최근 몇 분 동안의 결과를 가져올지 지정
        
    Returns:
        이상 탐지 결과 목록
    """
    # 현재 시간 기준으로 검색 범위 설정
    now = datetime.datetime.now()
    time_from = now - datetime.timedelta(minutes=minutes)
    
    # Elasticsearch 쿼리 작성
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": time_from.strftime('%Y-%m-%d %H:%M:%S'),
                                "lte": now.strftime('%Y-%m-%d %H:%M:%S')
                            }
                        }
                    },
                    {
                        "term": {
                            "is_anomaly": True
                        }
                    }
                ]
            }
        },
        "sort": [
            {"timestamp": {"order": "desc"}}
        ],
        "size": 100
    }
    
    # 쿼리 실행
    try:
        response = es.search(index=es_anomaly_index, body=query)
        
        # 결과 변환
        anomalies = []
        for hit in response['hits']['hits']:
            anomaly = hit['_source']
            anomalies.append(anomaly)
        
        return anomalies
    except Exception as e:
        logger.error(f"Elasticsearch 쿼리 중 오류 발생: {e}")
        return []

def determine_severity(anomaly):
    """
    이상 탐지 결과의 심각도를 판단합니다.
    
    Args:
        anomaly: 이상 탐지 결과 데이터
        
    Returns:
        심각도 레벨 ('low', 'medium', 'high', 'critical')
    """
    detector_type = anomaly.get('detector_type', 'unknown')
    
    if detector_type == 'isolation_forest':
        # 점수가 낮을수록 더 이상한 것 (Isolation Forest 특성)
        score = anomaly.get('anomaly_score', 0)
        if score < -0.7:
            return 'critical'
        elif score < -0.5:
            return 'high'
        elif score < -0.3:
            return 'medium'
        else:
            return 'low'
    
    elif detector_type == 'lstm':
        # 오차가 클수록 더 이상한 것
        error_ratio = anomaly.get('mean_error', 0) / anomaly.get('threshold', 1) if 'threshold' in anomaly else 0
        anomaly_ratio = anomaly.get('anomaly_count', 0) / max(anomaly.get('total_sequences', 1), 1)
        
        if error_ratio > 2.0 or anomaly_ratio > 0.5:
            return 'critical'
        elif error_ratio > 1.5 or anomaly_ratio > 0.3:
            return 'high'
        elif error_ratio > 1.2 or anomaly_ratio > 0.1:
            return 'medium'
        else:
            return 'low'
    
    elif detector_type == 'bert':
        # 거리가 클수록 더 이상한 것
        anomaly_ratio = anomaly.get('anomaly_count', 0) / max(anomaly.get('total_logs', 1), 1)
        
        if anomaly_ratio > 0.5:
            return 'critical'
        elif anomaly_ratio > 0.3:
            return 'high'
        elif anomaly_ratio > 0.1:
            return 'medium'
        else:
            return 'low'
    
    # 기본 심각도
    return 'medium'

def save_incident_to_elasticsearch(incident):
    """인시던트 정보를 Elasticsearch에 저장"""
    try:
        incident_data = incident.to_dict()
        es.index(index=es_incident_index, id=incident.incident_id, body=incident_data)
        logger.info(f"인시던트 저장 완료: {incident.incident_id}")
        return True
    except Exception as e:
        logger.error(f"인시던트 저장 중 오류 발생: {e}")
        return False

def update_incident_in_elasticsearch(incident):
    """인시던트 정보를 Elasticsearch에서 업데이트"""
    try:
        incident_data = incident.to_dict()
        es.update(index=es_incident_index, id=incident.incident_id, body={"doc": incident_data})
        logger.info(f"인시던트 업데이트 완료: {incident.incident_id}")
        return True
    except Exception as e:
        logger.error(f"인시던트 업데이트 중 오류 발생: {e}")
        return False
    """
SOAR 통합 모듈 (Part 3)
이상 탐지 결과를 SOAR 플랫폼(Shuffle)과 연동하여 자동화된 대응을 수행합니다.
"""

def get_incident_from_elasticsearch(incident_id):
    """Elasticsearch에서 인시던트 정보 조회"""
    try:
        response = es.get(index=es_incident_index, id=incident_id)
        incident_data = response['_source']
        
        # Incident 객체 생성
        incident = Incident(
            anomaly_data=incident_data['anomaly_data'],
            incident_id=incident_data['incident_id'],
            status=incident_data['status'],
            severity=incident_data['severity'],
            title=incident_data['title'],
            description=incident_data['description']
        )
        
        # 대응 조치 정보 복원
        incident.actions = incident_data['actions']
        incident.created_at = incident_data['created_at']
        incident.updated_at = incident_data['updated_at']
        
        return incident
    except Exception as e:
        logger.error(f"인시던트 조회 중 오류 발생: {incident_id}, {e}")
        return None

def trigger_shuffle_workflow(incident):
    """
    Shuffle 워크플로우를 트리거합니다.
    
    Args:
        incident: 인시던트 객체
        
    Returns:
        성공 여부 (True/False)
    """
    if SHUFFLE_API_KEY == 'YOUR_SHUFFLE_API_KEY' or SHUFFLE_WORKFLOW_ID == 'YOUR_WORKFLOW_ID':
        logger.warning("Shuffle API 키 또는 워크플로우 ID가 설정되지 않았습니다.")
        return False
    
    # Shuffle API 엔드포인트
    api_url = f"{SHUFFLE_API_URL}/workflows/{SHUFFLE_WORKFLOW_ID}/execute"
    
    # Shuffle에 전송할 데이터 준비
    payload = {
        "execution_argument": json.dumps(incident.to_dict()),
        "start_node": ""  # 시작 노드 ID (비워두면 첫 번째 노드부터 시작)
    }
    
    # API 헤더
    headers = {
        "Authorization": f"Bearer {SHUFFLE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        # API 호출
        response = requests.post(api_url, json=payload, headers=headers)
        
        if response.status_code == 200:
            execution_id = response.json().get('execution_id', 'unknown')
            logger.info(f"Shuffle 워크플로우 실행 성공: {incident.incident_id}, 실행 ID: {execution_id}")
            
            # 워크플로우 실행 정보 기록
            incident.add_action(
                action_type="workflow_execution",
                description=f"Shuffle 워크플로우 실행 시작 (실행 ID: {execution_id})"
            )
            
            # 인시던트 상태 업데이트
            incident.update_status("in_progress", "자동화된 워크플로우 실행 중")
            
            # Elasticsearch에 인시던트 업데이트
            update_incident_in_elasticsearch(incident)
            
            return True
        else:
            logger.error(f"Shuffle 워크플로우 실행 실패: {response.status_code}, {response.text}")
            
            # 실패 정보 기록
            incident.add_action(
                action_type="workflow_execution_failed",
                description=f"Shuffle 워크플로우 실행 실패: {response.status_code}, {response.text}"
            )
            
            # Elasticsearch에 인시던트 업데이트
            update_incident_in_elasticsearch(incident)
            
            return False
    except Exception as e:
        logger.error(f"Shuffle 워크플로우 실행 중 오류 발생: {e}")
        
        # 오류 정보 기록
        incident.add_action(
            action_type="workflow_execution_error",
            description=f"Shuffle 워크플로우 실행 중 오류 발생: {str(e)}"
        )
        
        # Elasticsearch에 인시던트 업데이트
        update_incident_in_elasticsearch(incident)
        
        return False

def fetch_related_logs(anomaly, time_window_minutes=30):
    """
    이상 탐지와 관련된 로그를 가져옵니다.
    
    Args:
        anomaly: 이상 탐지 결과 데이터
        time_window_minutes: 시간 범위 (분)
        
    Returns:
        관련 로그 목록
    """
    detector_type = anomaly.get('detector_type', 'unknown')
    timestamp = anomaly.get('timestamp')
    
    if not timestamp:
        logger.error("이상 탐지 결과에 타임스탬프가 없습니다.")
        return []
    
    # 타임스탬프를 datetime 객체로 변환
    try:
        timestamp_dt = datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        logger.error(f"타임스탬프 형식 오류: {timestamp}")
        return []
    
    # 검색 범위 설정
    time_from = timestamp_dt - datetime.timedelta(minutes=time_window_minutes)
    time_to = timestamp_dt + datetime.timedelta(minutes=5)  # 약간의 버퍼 추가
    
    # 기본 쿼리
    query = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": time_from.strftime('%Y-%m-%d %H:%M:%S'),
                                "lte": time_to.strftime('%Y-%m-%d %H:%M:%S')
                            }
                        }
                    }
                ]
            }
        },
        "sort": [
            {"timestamp": {"order": "asc"}}
        ],
        "size": 1000
    }
    
    # 탐지기 유형별 추가 필터링
    if detector_type == 'isolation_forest':
        # 특정 로그 레벨이나 컴포넌트를 필터링할 수 있음
        pass
    elif detector_type == 'lstm':
        # 특정 시퀀스 패턴에 관련된 로그를 필터링할 수 있음
        pass
    elif detector_type == 'bert':
        # 이상 로그 메시지와 유사한 로그를 찾을 수 있음
        pass
    
    # 쿼리 실행
    try:
        response = es.search(index=es_logs_index, body=query)
        
        # 결과 변환
        logs = []
        for hit in response['hits']['hits']:
            log = hit['_source']
            logs.append(log)
        
        return logs
    except Exception as e:
        logger.error(f"로그 검색 중 오류 발생: {e}")
        return []
"""
SOAR 통합 모듈 (Part 4)
이상 탐지 결과를 SOAR 플랫폼(Shuffle)과 연동하여 자동화된 대응을 수행합니다.
"""

def enrich_incident_with_context(incident):
    """
    인시던트에 컨텍스트 정보를 추가합니다.
    
    Args:
        incident: 인시던트 객체
        
    Returns:
        업데이트된 인시던트 객체
    """
    # 관련 로그 가져오기
    related_logs = fetch_related_logs(incident.anomaly_data)
    
    if related_logs:
        # 로그 샘플 (최대 10개)
        log_samples = related_logs[:10]
        
        # 로그 레벨별 통계
        log_level_counts = {}
        for log in related_logs:
            log_level = log.get('log_level', 'unknown')
            log_level_counts[log_level] = log_level_counts.get(log_level, 0) + 1
        
        # 컴포넌트별 통계
        component_counts = {}
        for log in related_logs:
            component = log.get('component', 'unknown')
            component_counts[component] = component_counts.get(component, 0) + 1
        
        # 컨텍스트 정보 추가
        context = {
            'related_logs_count': len(related_logs),
            'log_level_stats': log_level_counts,
            'component_stats': component_counts,
            'log_samples': log_samples
        }
        
        # 인시던트에 컨텍스트 추가
        incident.anomaly_data['context'] = context
        
        # 인시던트에 조치 기록
        incident.add_action(
            action_type="context_enrichment",
            description=f"관련 로그 {len(related_logs)}개를 추가하여 컨텍스트 정보 보강"
        )
    
    return incident

def process_anomalies():
    """
    주기적으로 새로운 이상 탐지 결과를 확인하고 SOAR 플랫폼으로 전송합니다.
    """
    global processed_incidents
    
    while True:
        try:
            # 최근 이상 탐지 결과 가져오기
            anomalies = fetch_recent_anomalies(minutes=10)
            
            for anomaly in anomalies:
                # 임시 ID 생성 (중복 처리 방지용)
                hash_input = f"{anomaly.get('timestamp', '')}_{anomaly.get('detector_type', '')}"
                if 'anomaly_score' in anomaly:
                    hash_input += f"_{anomaly['anomaly_score']}"
                elif 'mean_error' in anomaly:
                    hash_input += f"_{anomaly['mean_error']}"
                
                temp_id = hashlib.md5(hash_input.encode()).hexdigest()
                
                # 이미 처리한 인시던트인지 확인
                if temp_id in processed_incidents:
                    continue
                
                # 심각도 판단
                severity = determine_severity(anomaly)
                
                # 낮은 심각도는 무시 (선택 사항)
                if severity == 'low':
                    processed_incidents.add(temp_id)
                    continue
                
                # 인시던트 생성
                incident = Incident(anomaly_data=anomaly, severity=severity)
                
                # 컨텍스트 정보 추가
                incident = enrich_incident_with_context(incident)
                
                # Elasticsearch에 인시던트 저장
                save_incident_to_elasticsearch(incident)
                
                # SOAR 워크플로우 트리거
                if severity in ['high', 'critical']:
                    trigger_shuffle_workflow(incident)
                
                # 처리 완료 표시
                processed_incidents.add(temp_id)
                
                # 집합 크기 제한 (메모리 관리)
                if len(processed_incidents) > 1000:
                    # 오래된 항목 제거
                    processed_incidents = set(list(processed_incidents)[-500:])
            
            # 1분 대기
            time.sleep(60)
        except Exception as e:
            logger.error(f"이상 탐지 처리 중 오류 발생: {e}")
            time.sleep(60)  # 오류 발생 시 1분 대기 후 재시도

def init_elasticsearch_indices():
    """필요한 Elasticsearch 인덱스가 없으면 생성"""
    # 인시던트 인덱스 생성
    if not es.indices.exists(index=es_incident_index):
        mapping = {
            "mappings": {
                "properties": {
                    "incident_id": {"type": "keyword"},
                    "title": {"type": "text"},
                    "description": {"type": "text"},
                    "status": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "detector_type": {"type": "keyword"},
                    "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
                    "created_at": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
                    "updated_at": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
                    "anomaly_data": {"type": "object", "enabled": True},
                    "actions": {"type": "nested"}
                }
            },
            "settings": {
                "number_of_shards": 3,
                "number_of_replicas": 1
            }
        }
        es.indices.create(index=es_incident_index, body=mapping)
        logger.info(f"Elasticsearch 인덱스 생성 완료: {es_incident_index}")

if __name__ == '__main__':
    try:
        logger.info("SOAR 통합 모듈 시작...")
        
        # 환경 변수 확인
        if SHUFFLE_API_KEY == 'YOUR_SHUFFLE_API_KEY':
            logger.warning("Shuffle API 키가 설정되지 않았습니다. 환경 변수 SHUFFLE_API_KEY를 설정하세요.")
        
        if SHUFFLE_WORKFLOW_ID == 'YOUR_WORKFLOW_ID':
            logger.warning("Shuffle 워크플로우 ID가 설정되지 않았습니다. 환경 변수 SHUFFLE_WORKFLOW_ID를 설정하세요.")
        
        # Elasticsearch 인덱스 초기화
        init_elasticsearch_indices()
        
        # 이상 탐지 처리 루프 실행
        process_anomalies()
    except KeyboardInterrupt:
        logger.info("SOAR 통합 모듈 종료...")