FROM python:3.10-slim

WORKDIR /app

# 필요 패키지 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 디렉토리 생성
RUN mkdir -p /app/logs /var/log/url_blocker /etc/suricata/rules

# Python 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 복사
COPY app.py proxy_server.py url_blocker_manager.py ./
COPY model/catboost_url_model.cbm ./model/

# 로그 디렉토리 환경 변수 설정
ENV LOG_DIR=/app/logs
ENV PYTHONUNBUFFERED=1

# 볼륨 설정
VOLUME ["/app/logs", "/var/log/url_blocker", "/etc/suricata/rules"]

# 프록시 서버 포트 노출
EXPOSE 8888 5000

# 시작 스크립트 복사 및 실행 권한 부여
COPY start.sh .
RUN chmod +x start.sh

# 컨테이너 실행 시 시작 스크립트 실행
CMD ["./start.sh"]