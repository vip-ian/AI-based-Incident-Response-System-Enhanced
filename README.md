# AI 기반 로그 이상 탐지 및 인시던트 대응 시스템

이 프로젝트는 "AI 기반 인시던트 대응 시스템" 논문에 기반한 실시간 로그 이상 탐지 및 자동화된 대응 시스템의 구현입니다. 다양한 인공지능 모델(Isolation Forest, LSTM, BERT)을 병렬로 활용하여 로그 데이터에서 이상 징후를 포괄적으로 탐지하고, SOAR(Security Orchestration, Automation and Response) 플랫폼과 연계하여 자동화된 대응을 제공합니다.

## 시스템 아키텍처

시스템은 크게 다음 구성 요소로 이루어져 있습니다:

1. **로그 수집**: 다양한 소스에서 로그를 수집하여 Kafka로 전송
2. **로그 처리**: Kafka에서 로그를 가져와 Elasticsearch에 저장
3. **이상 탐지**: 세 가지 AI 모델을 통한 이상 탐지
   - Isolation Forest: 구조화된 데이터 분석
   - LSTM: 시퀀스 패턴 분석
   - BERT: 로그 메시지 의미 분석
4. **자동화된 대응**: 이상 탐지 결과에 대한 알림 및 SOAR 플랫폼 연계 대응

## 기술 스택

- **Python 3.9+**: 모든 구성 요소 구현
- **Apache Kafka**: 로그 메시지 스트리밍
- **Elasticsearch & Kibana**: 로그 저장, 인덱싱 및 시각화
- **PyTorch**: 딥러닝 모델(LSTM, BERT) 구현
- **scikit-learn**: Isolation Forest 알고리즘
- **Shuffle SOAR**: 자동화된 인시던트 대응 워크플로우

## 요구 사항

다음 서비스가 필요합니다:

- Kafka (로그 스트리밍용)
- Elasticsearch (로그 저장용)
- Kibana (시각화 - 선택 사항)
- Shuffle SOAR 플랫폼 (자동화된 대응용 - 선택 사항)

Python 패키지 요구 사항:
```
pandas>=1.5.0
numpy>=1.23.0
torch>=2.0.0
scikit-learn>=1.2.0
elasticsearch>=7.16.0
kafka-python>=2.0.2
joblib>=1.2.0
transformers>=4.28.0 (BERT 모델용)
requests>=2.28.0
```

## 설치 및 구성

### 1. 환경 설정

```bash
# 가상 환경 생성 (권장)
python -m venv incident-response-env
source incident-response-env/bin/activate  # Linux/Mac
# 또는
incident-response-env\Scripts\activate  # Windows

# 패키지 설치
pip install -r requirements.txt
```

### 2. 외부 서비스 구성

Docker Compose를 사용한 간편 설정:

```bash
# 서비스 실행
docker-compose up -d
```

로컬에서 직접 서비스를 설치하고 실행하려면 각 서비스별 공식 문서를 참조하세요.

### 3. 구성 파일 설정

`config/config.json` 파일을 생성하고 시스템 설정을 구성하세요:

```json
{
  "kafka": {
    "bootstrap_servers": ["localhost:9092"],
    "topic_name": "logs-topic",
    "group_id": "log-processor-group"
  },
  "elasticsearch": {
    "hosts": ["localhost:9200"],
    "logs_index": "logs",
    "anomaly_index": "log-anomalies",
    "incident_index": "security-incidents"
  },
  "notification": {
    "slack": {
      "webhook_url": "YOUR_SLACK_WEBHOOK_URL",
      "channel": "#security-alerts"
    },
    "email": {
      "smtp_server": "smtp.example.com",
      "smtp_port": 587,
      "from": "alerts@example.com",
      "password": "your-password",
      "to": ["security-team@example.com"]
    }
  },
  "soar": {
    "shuffle": {
      "api_url": "http://localhost:3001/api/v1",
      "api_key": "YOUR_SHUFFLE_API_KEY",
      "workflow_id": "YOUR_WORKFLOW_ID"
    }
  },
  "logs": {
    "directory": "logs/",
    "patterns": ["*.log"]
  }
}
```

## 사용 방법

### 1. 시스템 실행

전체 시스템을 한 번에 실행:

```bash
python main.py
```

### 2. 개별 구성 요소 실행

필요에 따라 개별 구성 요소를 독립적으로 실행할 수 있습니다:

```bash
# 로그 수집기 실행
python log_collector.py

# 로그 처리기 실행
python log_processor.py

# Isolation Forest 이상 탐지 실행
python isolation_forest_detector.py

# LSTM 시퀀스 이상 탐지 실행
python lstm_detector_pytorch.py

# BERT 로그 분석 실행
python bert_analyzer.py

# 알림 시스템 실행
python notification_system.py

# SOAR 통합 실행
python soar_integration.py
```

### 3. SOAR 워크플로우 구성

Shuffle SOAR 플랫폼에서 `incident_response_workflow.json` 파일을 가져와 워크플로우를 구성합니다:

1. Shuffle 웹 인터페이스에 접속 (기본: http://localhost:3001)
2. "Workflows" 메뉴로 이동
3. "New" 버튼 클릭
4. "Import" 탭 선택
5. `incident_response_workflow.json` 파일 업로드
6. 필요에 따라 앱 연결 및 액션 구성 수정

## 테스트 및 개발

### 테스트용 로그 생성

개발 및 테스트 목적으로 샘플 로그를 생성할 수 있습니다:

```bash
python generate_sample_logs.py
```

이 스크립트는 다양한 유형의 로그를 생성하고, 특정 확률로 이상 패턴을 포함합니다.

### 모니터링

Kibana 대시보드를 통해 시스템 활동을 모니터링할 수 있습니다:

1. Kibana에 접속 (기본: http://localhost:5601)
2. "Management" > "Stack Management" > "Index Patterns"로 이동
3. `logs*`, `log-anomalies*`, `security-incidents*` 패턴 생성
4. "Dashboard"에서 새 대시보드 생성

## 프로젝트 구조

```
ai-incident-response/
│
├── main.py                        # 메인 실행 스크립트
├── log_collector.py               # 로그 수집기
├── log_processor.py               # 로그 처리기
├── isolation_forest_detector.py   # Isolation Forest 이상 탐지
├── lstm_detector_pytorch.py       # LSTM 이상 탐지 (PyTorch)
├── bert_analyzer.py               # BERT 로그 분석
├── notification_system.py         # 알림 시스템
├── soar_integration.py            # SOAR 통합
├── generate_sample_logs.py        # 샘플 로그 생성기
│
├── config/                        # 설정 파일
│   └── config.json                # 시스템 설정
│
├── models/                        # 모델 저장 디렉토리
│
├── logs/                          # 로그 디렉토리
│
├── incident_response_workflow.json # SOAR 워크플로우 정의
├── docker-compose.yml             # Docker 구성 파일
├── Dockerfile                     # Docker 이미지 정의
│
├── requirements.txt               # Python 패키지 요구사항
└── README.md                      # 이 파일
```

## 확장 및 커스터마이징

시스템은 모듈식으로 설계되어 있어 다양한 방식으로 확장하고 커스터마이징할 수 있습니다:

1. **새로운 이상 탐지 알고리즘 추가**: `isolation_forest_detector.py`를 템플릿으로 사용하여 새로운 탐지 모듈 개발
2. **다양한 로그 소스 연동**: `log_collector.py`를 확장하여 추가 로그 소스 지원
3. **SOAR 워크플로우 커스터마이징**: `incident_response_workflow.json`을 수정하여 인시던트 대응 자동화 확장
4. **알림 채널 추가**: `notification_system.py`를 수정하여 추가 알림 채널 지원

## 문제 해결

일반적인 문제 및 해결 방법:

1. **Kafka 연결 문제**:
   ```bash
   docker-compose logs kafka
   ```

2. **Elasticsearch 인덱스 문제**:
   ```bash
   curl -X GET "localhost:9200/_cat/indices?v"
   ```

3. **모델 학습 문제**:
   - 충분한 학습 데이터가 있는지 확인
   - 로그 파일 검토

## 참고 문헌

- Lee, S., & Shon, T. (2025). "AI-based Incident Response System."
- Du, M., Li, F., Zheng, G., & Srikumar, V. (2017). "DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning."
- Zhang, J., Zhu, X., Wang, H., & Chen, J. (2021). "LogBERT: Log Anomaly Detection via BERT."

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 LICENSE 파일을 참조하세요.

## 연락처

문의사항이 있으시면 다음 연락처로 문의하세요:
- 이메일: your-email@example.com
