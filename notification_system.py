"""
알림 시스템
이상 탐지 결과를 Slack 및 이메일로 자동 알림합니다.
"""
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from elasticsearch import Elasticsearch
import json
import time
import datetime
import logging
import os

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("notification.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("notification_system")

# Elasticsearch 설정
es_hosts = ['localhost:9200']
es_anomaly_index = 'log-anomalies'

# Slack 설정
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', 'YOUR_SLACK_WEBHOOK_URL')
SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL', '#security-alerts')

# 이메일 설정
EMAIL_SMTP_SERVER = os.environ.get('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
EMAIL_SMTP_PORT = int(os.environ.get('EMAIL_SMTP_PORT', 587))
EMAIL_FROM = os.environ.get('EMAIL_FROM', 'your-email@example.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'your-email-password')
EMAIL_TO_LIST = os.environ.get('EMAIL_TO_LIST', 'recipient1@example.com,recipient2@example.com').split(',')

# 알림 설정
NOTIFICATION_COOLDOWN_SECONDS = 300  # 같은 유형의 알림을 재전송하기 전 대기 시간
SEVERITY_THRESHOLD = 0.7  # 심각도 임계값 (0.0 ~ 1.0)

# Elasticsearch 클라이언트 생성
es = Elasticsearch(es_hosts)

# 최근 알림 기록
recent_notifications = {}

def send_slack_notification(message, severity='medium', details=None):
    """
    Slack으로 알림을 전송합니다.
    
    Args:
        message: 알림 메시지
        severity: 심각도 ('low', 'medium', 'high', 'critical')
        details: 추가 세부 정보 (선택 사항)
    """
    # 심각도에 따른 색상 설정
    color_map = {
        'low': '#36a64f',  # 초록색
        'medium': '#ffd700',  # 노란색
        'high': '#ff9900',  # 주황색
        'critical': '#ff0000'  # 빨간색
    }
    color = color_map.get(severity, '#777777')
    
    # 요약을 위한 필드 준비
    fields = [
        {
            "title": "심각도",
            "value": severity.upper(),
            "short": True
        },
        {
            "title": "탐지 시간",
            "value": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "short": True
        }
    ]
    
    # 세부 정보가 있으면 추가
    if details:
        for key, value in details.items():
            fields.append({
                "title": key,
                "value": str(value),
                "short": True
            })
    
    # Slack 메시지 페이로드 생성
    payload = {
        "channel": SLACK_CHANNEL,
        "username": "보안 알림 봇",
        "icon_emoji": ":warning:",
        "attachments": [
            {
                "fallback": message,
                "pretext": "보안 알림이 발생했습니다!",
                "title": message,
                "color": color,
                "fields": fields,
                "footer": "AI 기반 로그 이상 탐지 시스템",
                "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                "ts": int(time.time())
            }
        ]
    }
    
    try:
        # Slack 웹훅으로 전송
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            logger.info(f"Slack 알림 전송 성공: {message}")
            return True
        else:
            logger.error(f"Slack 알림 전송 실패: {response.status_code}, {response.text}")
            return False
    except Exception as e:
        logger.error(f"Slack 알림 전송 중 오류 발생: {e}")
        return False

def send_email_notification(subject, message, severity='medium', details=None):
    """
    이메일로 알림을 전송합니다.
    
    Args:
        subject: 이메일 제목
        message: 이메일 본문 메시지
        severity: 심각도 ('low', 'medium', 'high', 'critical')
        details: 추가 세부 정보 (선택 사항)
    """
    try:
        # MIMEMultipart 객체 생성
        email = MIMEMultipart()
        email['From'] = EMAIL_FROM
        email['To'] = ', '.join(EMAIL_TO_LIST)
        
        # 심각도에 따른 제목 태그 추가
        if severity == 'critical':
            subject = f"[긴급] {subject}"
        elif severity == 'high':
            subject = f"[중요] {subject}"
        else:
            subject = f"[알림] {subject}"
        
        email['Subject'] = subject
        
        # HTML 본문 생성
        html_message = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .container {{ padding: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 10px; border-bottom: 1px solid #e9ecef; }}
                .content {{ padding: 15px 0; }}
                .footer {{ font-size: 12px; color: #6c757d; padding-top: 10px; border-top: 1px solid #e9ecef; }}
                .severity-low {{ color: #28a745; }}
                .severity-medium {{ color: #ffc107; }}
                .severity-high {{ color: #fd7e14; }}
                .severity-critical {{ color: #dc3545; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>보안 알림</h2>
                    <p>심각도: <span class="severity-{severity}">{severity.upper()}</span></p>
                    <p>시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <div class="content">
                    <p>{message}</p>
        """
        
        # 상세 정보가 있으면 테이블 형태로 추가
        if details:
            html_message += """
                    <h3>상세 정보</h3>
                    <table>
                        <tr>
                            <th>항목</th>
                            <th>값</th>
                        </tr>
            """
            
            for key, value in details.items():
                html_message += f"""
                        <tr>
                            <td>{key}</td>
                            <td>{value}</td>
                        </tr>
                """
            
            html_message += """
                    </table>
            """
        
        # 푸터 추가 및 HTML 닫기
        html_message += """
                </div>
                <div class="footer">
                    <p>이 알림은 AI 기반 로그 이상 탐지 시스템에서 자동으로 생성되었습니다.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # 본문 첨부
        email.attach(MIMEText(html_message, 'html'))
        
        # SMTP 서버 연결 및 이메일 전송
        with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(email)
        
        logger.info(f"이메일 알림 전송 성공: {subject}")
        return True
    except Exception as e:
        logger.error(f"이메일 알림 전송 중 오류 발생: {e}")
        return False

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

def format_anomaly_details(anomaly):
    """
    이상 탐지 결과의 상세 정보를 형식화합니다.
    """
    details = {}
    detector_type = anomaly.get('detector_type', 'unknown')
    
    # 공통 정보
    details['탐지 시간'] = anomaly.get('timestamp', 'N/A')
    details['탐지기 유형'] = detector_type
    
    # 탐지기 유형별 상세 정보
    if detector_type == 'isolation_forest':
        details['이상 점수'] = f"{anomaly.get('anomaly_score', 0):.4f}"
        details['로그 수'] = anomaly.get('log_count', 0)
        details['시간 범위'] = f"{anomaly.get('time_window_minutes', 0)}분"
    
    elif detector_type == 'lstm':
        details['평균 오차'] = f"{anomaly.get('mean_error', 0):.4f}"
        details['최대 오차'] = f"{anomaly.get('max_error', 0):.4f}"
        details['이상 시퀀스'] = f"{anomaly.get('anomaly_count', 0)}/{anomaly.get('total_sequences', 0)}"
        details['시간 범위'] = f"{anomaly.get('time_window_minutes', 0)}분"
    
    elif detector_type == 'bert':
        details['평균 거리'] = f"{anomaly.get('mean_distance', 0):.4f}"
        details['최대 거리'] = f"{anomaly.get('max_distance', 0):.4f}"
        details['이상 로그'] = f"{anomaly.get('anomaly_count', 0)}/{anomaly.get('total_logs', 0)}"
        details['시간 범위'] = f"{anomaly.get('time_window_minutes', 0)}분"
    
    return details

def should_send_notification(anomaly, severity):
    """
    알림을 보내야 하는지 판단합니다.
    쿨다운 시간 내에 같은 유형의 알림이 이미 전송되었으면 무시합니다.
    """
    global recent_notifications
    
    detector_type = anomaly.get('detector_type', 'unknown')
    current_time = time.time()
    
    # 심각도가 낮으면 알림 보내지 않음
    if severity == 'low':
        return False
    
    # 심각도가 'critical'이면 항상 알림
    if severity == 'critical':
        # 그래도 최소 1분은 간격을 두자
        if detector_type in recent_notifications:
            last_time = recent_notifications[detector_type]
            if current_time - last_time < 60:
                return False
    else:
        # 쿨다운 체크
        if detector_type in recent_notifications:
            last_time = recent_notifications[detector_type]
            if current_time - last_time < NOTIFICATION_COOLDOWN_SECONDS:
                return False
    
    # 알림 시간 업데이트
    recent_notifications[detector_type] = current_time
    return True

def process_anomalies():
    """주기적으로 새로운 이상 탐지 결과를 확인하고 알림을 전송합니다."""
    while True:
        try:
            # 최근 이상 탐지 결과 가져오기
            anomalies = fetch_recent_anomalies(minutes=5)
            
            for anomaly in anomalies:
                # 심각도 판단
                severity = determine_severity(anomaly)
                
                # 알림 보내야 하는지 확인
                if should_send_notification(anomaly, severity):
                    detector_type = anomaly.get('detector_type', 'unknown').upper()
                    detector_map = {
                        'ISOLATION_FOREST': '구조화 데이터 분석',
                        'LSTM': '시퀀스 패턴 분석',
                        'BERT': '로그 메시지 의미 분석'
                    }
                    detector_name = detector_map.get(detector_type, detector_type)
                    
                    # 알림 메시지 생성
                    message = f"{detector_name}에서 비정상 로그 패턴이 감지되었습니다."
                    details = format_anomaly_details(anomaly)
                    
                    # Slack 알림 전송
                    send_slack_notification(message, severity, details)
                    
                    # 이메일 알림 (심각도가 높은 경우에만)
                    if severity in ['high', 'critical']:
                        subject = f"보안 경고: {detector_name}에서 비정상 패턴 감지"
                        send_email_notification(subject, message, severity, details)
            
            # 60초 대기
            time.sleep(60)
        except Exception as e:
            logger.error(f"알림 처리 중 오류 발생: {e}")
            time.sleep(60)  # 오류 발생 시 1분 대기 후 재시도

if __name__ == '__main__':
    try:
        logger.info("알림 시스템 시작...")
        
        # 환경 변수 확인
        if SLACK_WEBHOOK_URL == 'YOUR_SLACK_WEBHOOK_URL':
            logger.warning("Slack 웹훅 URL이 설정되지 않았습니다. 환경 변수 SLACK_WEBHOOK_URL을 설정하세요.")
        
        if EMAIL_PASSWORD == 'your-email-password':
            logger.warning("이메일 비밀번호가 설정되지 않았습니다. 환경 변수 EMAIL_PASSWORD를 설정하세요.")
        
        # 알림 처리 루프 실행
        process_anomalies()
    except KeyboardInterrupt:
        logger.info("알림 시스템 종료...")