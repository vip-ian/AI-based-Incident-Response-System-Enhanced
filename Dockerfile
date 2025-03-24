FROM python:3.9-slim

WORKDIR /app

# 기본 패키지 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 필요한 Python 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 소스 코드 복사
COPY *.py ./
COPY config/ ./config/

# 필요한 디렉토리 생성
RUN mkdir -p logs models

# 진입점 스크립트 실행
ENTRYPOINT ["python", "main.py"]