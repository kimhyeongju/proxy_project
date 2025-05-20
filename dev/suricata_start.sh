#!/bin/bash

# 필요한 디렉토리 생성
mkdir -p /var/log/suricata
mkdir -p /etc/suricata/rules
mkdir -p /var/log/url_blocker

# Suricata 환경 설정
echo "Configuring Suricata..."
# suricata.yaml 설정 파일 복사 및 수정
cp /app/suricata.yaml /etc/suricata/suricata.yaml

# EVE 로깅 활성화 및 경로 설정
sed -i 's|enabled: no|enabled: yes|g' /etc/suricata/suricata.yaml
sed -i 's|filename: eve.json|filename: /var/log/suricata/eve.json|g' /etc/suricata/suricata.yaml

# HTTP 로깅 활성화
sed -i '/http-log:/,/enabled:/ s/enabled: no/enabled: yes/' /etc/suricata/suricata.yaml

# 사용자 정의 규칙 파일 경로 추가
if ! grep -q "malicious_urls.rules" /etc/suricata/suricata.yaml; then
    echo "  - malicious_urls.rules" >> /etc/suricata/suricata.yaml
fi

# 빈 규칙 파일 생성 (없는 경우)
touch /etc/suricata/rules/malicious_urls.rules

# Flask 서버 URL 환경 변수 설정 (기본값 제공)
export FLASK_SERVER_URL=${FLASK_SERVER_URL:-"http://url-classifier:5000/predict"}

# Suricata 시작 (인터페이스 설정, Docker 네트워크 인터페이스 사용)
echo "Starting Suricata..."
suricata -c /etc/suricata/suricata.yaml -i eth0 &
SURICATA_PID=$!

# Suricata가 시작되기를 기다림
sleep 5

# Suricata 모니터 시작
echo "Starting Suricata Monitor..."
python3 /app/suricata_monitor.py &
MONITOR_PID=$!

# 서비스 상태 확인
echo "Services started:"
echo "Suricata PID: $SURICATA_PID"
echo "Monitor PID: $MONITOR_PID"

# PID 파일 생성
echo $SURICATA_PID > /var/run/suricata.pid
echo $MONITOR_PID > /var/run/monitor.pid

# SIGTERM 시그널 핸들링
trap 'kill $SURICATA_PID $MONITOR_PID; exit 0' SIGTERM

# 무한 대기 (컨테이너가 계속 실행되도록)
wait $SURICATA_PID