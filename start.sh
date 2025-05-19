#!/bin/bash

# 로그 디렉토리 생성
mkdir -p /app/logs
mkdir -p /var/log/url_blocker
mkdir -p /etc/suricata/rules

echo "=== URL Blocker 시스템 시작 ==="

# Flask 서버 시작 (백그라운드)
echo "Starting Flask server..."
python app.py &
FLASK_PID=$!

# 3초 대기하여 Flask 서버가 시작되도록 함
sleep 3

# 프록시 서버 시작 (백그라운드)
echo "Starting Proxy server..."
python proxy_server.py --host 0.0.0.0 --port 8888 &
PROXY_PID=$!

# url_blocker_manager.py를 통한 관리
echo "Starting URL Blocker Manager..."
python url_blocker_manager.py start

# SIGTERM 시그널 처리
cleanup() {
    echo "Stopping services..."
    kill $FLASK_PID $PROXY_PID
    python url_blocker_manager.py stop
    exit 0
}

trap cleanup SIGTERM SIGINT

# 상태 확인
echo "Services started:"
echo "Flask server PID: $FLASK_PID"
echo "Proxy server PID: $PROXY_PID"

# 서비스 상태 확인
python url_blocker_manager.py status

# 무한 대기 (컨테이너가 유지되도록)
tail -f /app/logs/*.log