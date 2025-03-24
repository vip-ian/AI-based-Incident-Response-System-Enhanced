"""
AI 기반 로그 이상 탐지 및 인시던트 대응 시스템 - 메인 스크립트
논문 "AI-based Incident Response System" 구현
"""
import os
import time
import subprocess
import threading
import logging
import signal
import sys
from pathlib import Path

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("main.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("main")

# 실행할 모듈들 정의
MODULES = [
    {
        "name": "로그 수집기",
        "script": "log_collector.py",
        "required": True,
        "description": "로그 파일을 모니터링하고 Kafka로 전송"
    },
    {
        "name": "로그 처리기",
        "script": "log_processor.py",
        "required": True,
        "description": "Kafka에서 로그를 가져와 Elasticsearch에 저장"
    },
    {
        "name": "Isolation Forest 이상 탐지",
        "script": "isolation_forest_detector.py",
        "required": False,
        "description": "구조화된 로그 데이터 분석"
    },
    {
        "name": "LSTM 이상 탐지",
        "script": "lstm_detector.py",
        "required": False,
        "description": "시퀀스 기반 로그 패턴 분석"
    },
    {
        "name": "BERT 로그 분석",
        "script": "bert_analyzer.py",
        "required": False,
        "description": "로그 메시지 의미 기반 분석"
    },
    {
        "name": "알림 시스템",
        "script": "notification_system.py",
        "required": False,
        "description": "이상 탐지 알림 전송"
    },
    {
        "name": "SOAR 통합",
        "script": "soar_integration.py",
        "required": False,
        "description": "자동화된 인시던트 대응"
    }
]

# 프로세스 및 스레드 저장
processes = {}
threads = {}


def check_prerequisites():
    """필요한 환경 및 종속성 확인"""
    logger.info("시스템 전제 조건 확인 중...")
    
    # 필요한 디렉토리 확인 및 생성
    dirs_to_check = ["logs", "models", "config"]
    for dir_name in dirs_to_check:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            logger.info(f"디렉토리 생성됨: {dir_name}")
    
    # 모듈 파일 확인
    missing_modules = []
    for module in MODULES:
        if not os.path.exists(module["script"]):
            missing_modules.append(module["script"])
    
    if missing_modules:
        if any(module["script"] in missing_modules for module in MODULES if module["required"]):
            logger.error(f"필수 모듈 파일이 누락되었습니다: {', '.join(missing_modules)}")
            return False
        else:
            logger.warning(f"일부 선택적 모듈 파일이 누락되었습니다: {', '.join(missing_modules)}")
    
    # 서비스 접근성 확인 (실제 환경에서는 더 상세한 확인 필요)
    services_to_check = [
        {"name": "Kafka", "host": "localhost", "port": 9092},
        {"name": "Elasticsearch", "host": "localhost", "port": 9200}
    ]
    
    import socket
    for service in services_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((service["host"], service["port"]))
        sock.close()
        
        if result != 0:
            logger.error(f"{service['name']} 서비스가 {service['host']}:{service['port']}에서 실행 중이 아닙니다.")
            return False
        else:
            logger.info(f"{service['name']} 서비스 접근 확인 완료")
    
    return True


def run_module(module):
    """모듈 스크립트 실행"""
    try:
        logger.info(f"{module['name']} 시작 중...")
        
        # Python 인터프리터 경로 (venv 사용 시 수정 필요)
        interpreter = sys.executable
        
        # 스크립트 경로
        script_path = os.path.join(os.getcwd(), module["script"])
        
        # 서브프로세스 시작
        process = subprocess.Popen(
            [interpreter, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # 줄 단위 버퍼링
        )
        
        # 프로세스 저장
        processes[module["name"]] = process
        
        # 출력 로깅 함수
        def log_output(pipe, log_level):
            prefix = f"[{module['name']}] "
            for line in iter(pipe.readline, ''):
                if not line.strip():
                    continue
                
                if log_level == logging.INFO:
                    logger.info(prefix + line.strip())
                else:
                    logger.error(prefix + line.strip())
        
        # stdout와 stderr 로깅 스레드 시작
        stdout_thread = threading.Thread(
            target=log_output,
            args=(process.stdout, logging.INFO),
            daemon=True
        )
        stderr_thread = threading.Thread(
            target=log_output,
            args=(process.stderr, logging.ERROR),
            daemon=True
        )
        
        stdout_thread.start()
        stderr_thread.start()
        
        # 스레드 저장
        threads[module["name"]] = {
            "stdout": stdout_thread,
            "stderr": stderr_thread
        }
        
        logger.info(f"{module['name']} 시작됨 (PID: {process.pid})")
        return True
    
    except Exception as e:
        logger.error(f"{module['name']} 시작 중 오류 발생: {e}")
        return False


def stop_module(module):
    """모듈 스크립트 중지"""
    name = module["name"]
    if name in processes:
        logger.info(f"{name} 중지 중...")
        
        # 프로세스 종료
        try:
            processes[name].terminate()
            processes[name].wait(timeout=5)
            logger.info(f"{name} 정상 종료됨")
        except subprocess.TimeoutExpired:
            logger.warning(f"{name} 강제 종료 중...")
            processes[name].kill()
            logger.info(f"{name} 강제 종료됨")
        except Exception as e:
            logger.error(f"{name} 종료 중 오류 발생: {e}")
        
        # 프로세스 및 스레드 정리
        del processes[name]
        if name in threads:
            del threads[name]


def start_all_modules():
    """모든 모듈 시작"""
    logger.info("모든 모듈 시작 중...")
    
    # 필수 모듈 먼저 시작
    required_modules = [m for m in MODULES if m["required"]]
    optional_modules = [m for m in MODULES if not m["required"]]
    
    # 필수 모듈 시작
    for module in required_modules:
        success = run_module(module)
        if not success:
            logger.error(f"필수 모듈 {module['name']} 시작 실패. 시스템을 중지합니다.")
            stop_all_modules()
            return False
        time.sleep(2)  # 모듈 간 시작 지연
    
    # 선택적 모듈 시작
    for module in optional_modules:
        if os.path.exists(module["script"]):
            run_module(module)
            time.sleep(2)  # 모듈 간 시작 지연
    
    return True


def stop_all_modules():
    """모든 모듈 중지"""
    logger.info("모든 모듈 중지 중...")
    
    # 역순으로 중지 (의존성 때문에)
    for module in reversed(MODULES):
        if module["name"] in processes:
            stop_module(module)
            time.sleep(1)  # 모듈 간 종료 지연


def signal_handler(sig, frame):
    """시그널 핸들러"""
    logger.info("종료 신호 수신. 정리 중...")
    stop_all_modules()
    logger.info("시스템이 정상적으로 종료되었습니다.")
    sys.exit(0)


def monitor_processes():
    """실행 중인 프로세스 모니터링"""
    while True:
        for module in MODULES:
            name = module["name"]
            if name in processes:
                process = processes[name]
                return_code = process.poll()
                
                # 프로세스가 종료된 경우
                if return_code is not None:
                    if return_code != 0:
                        logger.warning(f"{name} 모듈이 비정상 종료됨 (반환 코드: {return_code})")
                        
                        # 필수 모듈인 경우 재시작
                        if module["required"]:
                            logger.info(f"필수 모듈 {name} 재시작 중...")
                            run_module(module)
                    else:
                        logger.info(f"{name} 모듈이 정상 종료됨")
                        
                        # 프로세스 및 스레드 정리
                        del processes[name]
                        if name in threads:
                            del threads[name]
        
        time.sleep(5)  # 5초마다 확인


def main():
    """메인 함수"""
    logger.info("AI 기반 로그 이상 탐지 및 인시던트 대응 시스템 시작")
    
    # 시그널 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 전제 조건 확인
    if not check_prerequisites():
        logger.error("시스템 전제 조건이 충족되지 않았습니다. 종료합니다.")
        return
    
    # 모든 모듈 시작
    if not start_all_modules():
        return
    
    # 프로세스 모니터링
    try:
        monitor_processes()
    except KeyboardInterrupt:
        logger.info("사용자에 의한 중단...")
    finally:
        stop_all_modules()
        logger.info("시스템이 종료되었습니다.")


if __name__ == "__main__":
    main()