#!/bin/bash

# URL 분류 시스템을 위한 환경 설정 스크립트
# 이 스크립트는 Docker 컨테이너를 실행하기 전에 필요한 디렉토리를 생성하고 권한을 설정합니다.

# 색상 설정
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 함수: 메시지 출력
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 함수: 필요한 디렉토리 생성 및 권한 설정
setup_directories() {
    print_info "URL 분류 시스템 환경 설정을 시작합니다..."
    
    # 기본 디렉토리 경로 설정
    BASE_DIR="$HOME/url_classifier"
    print_info "기본 디렉토리: $BASE_DIR"
    
    # 필요한 디렉토리 목록
    directories=(
        "logs"
        "model"
        "suricata_logs"
        "suricata_rules"
        "blocked_urls"
    )
    
    # 기본 디렉토리 생성
    mkdir -p "$BASE_DIR"
    
    if [ $? -ne 0 ]; then
        print_error "기본 디렉토리 생성 실패: $BASE_DIR"
        exit 1
    fi
    
    # 하위 디렉토리 생성 및 권한 설정
    for dir in "${directories[@]}"; do
        mkdir -p "$BASE_DIR/$dir"
        
        if [ $? -ne 0 ]; then
            print_error "디렉토리 생성 실패: $BASE_DIR/$dir"
            continue
        fi
        
        # 권한 설정 (777: 모든 사용자에게 읽기/쓰기/실행 권한 부여)
        chmod -R 777 "$BASE_DIR/$dir"
        
        if [ $? -ne 0 ]; then
            print_error "권한 설정 실패: $BASE_DIR/$dir"
            continue
        fi
        
        print_success "디렉토리 생성 및 권한 설정 완료: $BASE_DIR/$dir"
    done
    
    print_success "모든 디렉토리 설정이 완료되었습니다."
}

# 함수: 모델 파일 확인
check_model_file() {
    MODEL_PATH="$HOME/url_classifier/model/catboost_url_model.cbm"
    
    if [ -f "$MODEL_PATH" ]; then
        print_success "모델 파일이 존재합니다: $MODEL_PATH"
    else
        print_warning "모델 파일이 없습니다: $MODEL_PATH"
        print_warning "Docker 컨테이너를 실행하기 전에 모델 파일을 준비해야 합니다."
        print_info "예시 명령: cp /path/to/catboost_url_model.cbm $MODEL_PATH"
    fi
}

# 함수: Docker Compose 파일 생성
create_docker_compose_file() {
    COMPOSE_PATH="$HOME/url_classifier/docker-compose.yml"
    
    # 호스트 IP 주소 가져오기
    HOST_IP=$(hostname -I | awk '{print $1}')
    
    # Docker Compose 파일 생성
    cat > "$COMPOSE_PATH" << EOF
version: '3'

services:
  # URL 분류 서비스 (Flask API 및 프록시 서버)
  url-classifier:
    image: hyeongju6/url-classifier:v1
    container_name: url-classifier
    ports:
      - "8888:8888"  # 프록시 서버 포트
      - "5000:5000"  # Flask API 포트
    volumes:
      - ./logs:/app/logs  # 로그 디렉토리 마운트
      - ./model:/app/model  # 모델 디렉토리 마운트
    environment:
      - LOG_DIR=/app/logs
    restart: unless-stopped
    networks:
      - url-classifier-net

  # Suricata IDS/IPS 서비스
  suricata:
    image: hyeongju6/url-suricata:v1
    container_name: suricata
    # 호스트 네트워크 모드 사용 (네트워크 트래픽 직접 모니터링 위함)
    network_mode: host
    cap_add:
      - NET_ADMIN  # 네트워크 관리 권한
      - NET_RAW    # RAW 소켓 권한
      - SYS_NICE   # 프로세스 우선순위 설정 권한
    volumes:
      - ./suricata_logs:/var/log/suricata  # Suricata 로그 디렉토리 마운트
      - ./suricata_rules:/etc/suricata/rules  # Suricata 규칙 디렉토리 마운트
      - ./blocked_urls:/var/log/url_blocker  # 차단된 URL 로그 마운트
    environment:
      - FLASK_SERVER_URL=http://${HOST_IP}:5000/predict  # Flask 서버 URL 설정
      - LOG_DIR=/var/log/url_blocker
    restart: unless-stopped
    depends_on:
      - url-classifier

networks:
  url-classifier-net:
    driver: bridge
EOF
    
    if [ $? -ne 0 ]; then
        print_error "Docker Compose 파일 생성 실패"
        exit 1
    fi
    
    print_success "Docker Compose 파일이 생성되었습니다: $COMPOSE_PATH"
}

# 함수: 상태 확인 스크립트 생성
create_status_check_script() {
    STATUS_SCRIPT_PATH="$HOME/url_classifier/check_status.sh"
    
    cat > "$STATUS_SCRIPT_PATH" << 'EOF'
#!/bin/bash

echo -e "\n=== URL Blocker 서비스 상태 ===\n"

# 컨테이너 상태 확인
echo "컨테이너 상태:"
docker ps --format "{{.Names}}: {{.Status}}" | grep -E 'url-classifier|suricata'

if [ $? -ne 0 ]; then
  echo "✗ 실행 중인 URL Blocker 컨테이너가 없습니다."
fi

# API 서버 확인
echo -e "\nAPI 서버 상태:"
HEALTH_RESPONSE=$(curl -s http://localhost:5000/health)

if [[ $HEALTH_RESPONSE == *"healthy"* ]]; then
  echo "✓ API 서버: 실행 중"
else
  echo "✗ API 서버: 응답 없음"
fi

# 차단 통계 확인
echo -e "\n=== 차단 통계 ===\n"

BLOCKED_LOG=~/url_classifier/logs/blocked_urls.log

if [ ! -f "$BLOCKED_LOG" ]; then
  echo "차단된 URL이 없습니다."
else
  # 전체 차단 수
  TOTAL_BLOCKS=$(cat "$BLOCKED_LOG" | wc -l)
  echo "총 차단 수: $TOTAL_BLOCKS"
  
  # 최근 24시간 차단 수 (간단한 근사치)
  YESTERDAY=$(date -d "yesterday" +%Y-%m-%d)
  TODAY=$(date +%Y-%m-%d)
  RECENT_BLOCKS=$(grep -E "$YESTERDAY|$TODAY" "$BLOCKED_LOG" | wc -l)
  echo "최근 24시간 차단 수 (근사치): $RECENT_BLOCKS"
  
  # 가장 많이 차단된 도메인
  echo -e "\n가장 많이 차단된 도메인:"
  cat "$BLOCKED_LOG" | grep -o '"url":"[^"]*"' | sed 's/"url":"http[s]*:\/\///g' | sed 's/\/.*//g' | sort | uniq -c | sort -nr | head -5 | awk '{print "  - " $2 ": " $1 "회"}'
fi

# Suricata 로그 확인
echo -e "\nSuricata 로그 상태:"
if [ -f ~/url_classifier/suricata_logs/eve.json ]; then
  LAST_LOG=$(tail -1 ~/url_classifier/suricata_logs/eve.json)
  if [ -n "$LAST_LOG" ]; then
    echo "✓ Suricata 로그: 활성 (마지막 이벤트 있음)"
  else
    echo "✗ Suricata 로그: 파일은 있으나 비어 있음"
  fi
else
  echo "✗ Suricata 로그 파일이 없음"
fi

# 프록시 설정 정보 제공
echo -e "\n=== 프록시 설정 정보 ===\n"
echo "Firefox 프록시 설정 방법:"
echo "1. Firefox 설정 > 네트워크 설정"
echo "2. '수동 프록시 설정' 선택"
echo "3. HTTP 프록시: $(hostname -I | awk '{print $1}')"
echo "4. 포트: 8888"
echo "5. 'HTTPS에도 이 프록시 서버 사용' 체크"
echo "6. 저장"
EOF
    
    # 실행 권한 부여
    chmod +x "$STATUS_SCRIPT_PATH"
    
    if [ $? -ne 0 ]; then
        print_error "상태 확인 스크립트 생성 실패"
        exit 1
    fi
    
    print_success "상태 확인 스크립트가 생성되었습니다: $STATUS_SCRIPT_PATH"
}

# 메인 함수
main() {
    # 디렉토리 설정
    setup_directories
    
    # 모델 파일 확인
    check_model_file
    
    # Docker Compose 파일 생성
    create_docker_compose_file
    
    # 상태 확인 스크립트 생성
    create_status_check_script
    
    print_info "환경 설정이 완료되었습니다."
    
    # 다음 단계 안내
    echo ""
    print_info "다음 단계:"
    echo "1. 모델 파일이 없는 경우 ~/url_classifier/model/ 디렉토리에 모델 파일을 복사하세요."
    echo "huggingface!!"
    echo ""
    echo "2. Docker Compose로 컨테이너를 시작하세요."
    echo "   명령어: cd ~/url_classifier && sudo docker-compose up -d"
    echo ""
    echo "3. 서비스 상태를 확인하세요."
    echo "   명령어: sudo ~/url_classifier/check_status.sh"
}

# 스크립트 실행
main
