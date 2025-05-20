#!/usr/bin/env python3
import json
import requests
import re
import logging
import subprocess
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
from urllib.parse import urlparse

# 로그 디렉토리 설정
LOG_DIR = "/var/log/url_blocker"
os.makedirs(LOG_DIR, exist_ok=True)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'suricata_monitor.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('suricata_monitor')

# Flask 서버 URL
FLASK_SERVER_URL = os.environ.get('FLASK_SERVER_URL', 'http://url-classifier:5000/predict')
logger.info(f"Using Flask server URL: {FLASK_SERVER_URL}")

# Suricata 규칙 파일 경로
SURICATA_RULES_PATH = '/etc/suricata/rules/malicious_urls.rules'

# Suricata EVE 로그 경로
SURICATA_EVE_LOG = '/var/log/suricata/eve.json'

# 차단 로그 파일
BLOCK_LOG_FILE = '/var/log/url_blocker/blocked_urls.log'

# 차단된 URL 캐시 (중복 확인용)
blocked_urls_cache = set()

# 화이트리스트 도메인
WHITELIST_DOMAINS = [
    'connectivity-check.ubuntu.com',
    'detectportal.firefox.com',
    'captive.apple.com',
    'connectivitycheck.gstatic.com',
    'msftconnecttest.com',
    'www.msftconnecttest.com',
    'ocsp.sectigo.com',
    'ocsp.digicert.com',
    'ocsp.pki.goog',
    'ocsp.verisign.com',
    'ocsp.entrust.net',
    'ocsp.comodoca.com',
    'ocsp.godaddy.com',
    'ocsp.globalsign.com',
    'ocsp.usertrust.com',
    'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com',
    'unpkg.com',
    'update.googleapis.com',
    'safebrowsing.googleapis.com',
    'accounts.google.com',
    'api.github.com',
    'auth.docker.io',
    'registry.npmjs.org',
    'pypi.org',
    'localhost',
    '127.0.0.1'
]

def is_whitelisted(url):
    """URL이 화이트리스트에 있는지 확인"""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        for whitelist_domain in WHITELIST_DOMAINS:
            if hostname == whitelist_domain or hostname.endswith('.' + whitelist_domain):
                return True
        
        return False
    except Exception as e:
        logger.error(f"화이트리스트 확인 중 오류: {e}")
        return False

class SuricataLogHandler(FileSystemEventHandler):
    """Suricata EVE JSON 로그를 모니터링하는 핸들러"""
    
    def __init__(self):
        self.file_position = 0
        # EVE 로그 파일이 없을 경우 빈 파일 생성
        if not os.path.exists(SURICATA_EVE_LOG):
            open(SURICATA_EVE_LOG, 'a').close()
            logger.info(f"Created empty Suricata log file: {SURICATA_EVE_LOG}")
        else:
            self.file_position = os.path.getsize(SURICATA_EVE_LOG)
            logger.info(f"Found existing Suricata log file, size: {self.file_position}")
    
    def on_modified(self, event):
        if event.src_path == SURICATA_EVE_LOG:
            self.process_new_logs()
    
    def process_new_logs(self):
        """새로운 로그 라인을 처리"""
        try:
            with open(SURICATA_EVE_LOG, 'r') as f:
                f.seek(self.file_position)
                
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        
                        # HTTP 이벤트만 처리
                        if log_entry.get('event_type') == 'http':
                            self.process_http_event(log_entry)
                    
                    except json.JSONDecodeError:
                        continue
                
                self.file_position = f.tell()
        
        except Exception as e:
            logger.error(f"로그 처리 중 오류: {e}")
    
    def process_http_event(self, event):
        """HTTP 이벤트에서 URL 추출 및 검사"""
        try:
            http_data = event.get('http', {})
            hostname = http_data.get('hostname', '')
            url_path = http_data.get('url', '/')
            
            # 전체 URL 구성
            full_url = f"http://{hostname}{url_path}"
            
            # 화이트리스트 확인
            if is_whitelisted(full_url):
                logger.debug(f"화이트리스트 URL: {full_url}")
                return
            
            # 이미 차단된 URL인지 확인
            if full_url in blocked_urls_cache:
                return
            
            # Flask 서버에 URL 분류 요청
            logger.info(f"Checking URL: {full_url}")
            try:
                response = requests.post(FLASK_SERVER_URL, json={'url': full_url}, timeout=5)
                
                if response.status_code == 200:
                    result = response.json()
                    probability = result.get('probability', 0)
                    
                    logger.info(f"Classification result for {full_url}: {result}")
                    
                    if result.get('is_malicious'):
                        logger.warning(f"악성 URL 탐지: {full_url} - 확률: {probability:.4f}")
                        self.block_url(full_url, probability, event)
                else:
                    logger.error(f"Flask server returned status {response.status_code}: {response.text}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Flask 서버 연결 오류: {e}")
            
        except Exception as e:
            logger.error(f"HTTP 이벤트 처리 중 오류: {e}")
    
    def block_url(self, url, probability, event):
        """악성 URL을 차단"""
        try:
            # URL에서 도메인 추출
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # 도메인이 비어있으면 처리하지 않음
            if not domain:
                logger.warning(f"도메인을 추출할 수 없음: {url}")
                return
            
            logger.info(f"Blocking domain: {domain}")
            
            # Suricata 규칙 생성
            rule_id = abs(hash(url)) % 1000000
            rule = f'drop http any any -> any any (msg:"Malicious URL blocked: {domain}"; http.host; content:"{domain}"; sid:{rule_id}; rev:1;)'
            
            # 규칙 추가
            self.add_suricata_rule(rule)
            
            # 캐시에 추가
            blocked_urls_cache.add(url)
            
            # 차단 로그 작성
            self.log_blocked_url(url, probability, event)
            
        except Exception as e:
            logger.error(f"URL 차단 중 오류: {e}")
    
    def add_suricata_rule(self, rule):
        """Suricata 규칙 파일에 규칙 추가"""
        try:
            # 규칙 파일이 없으면 생성
            if not os.path.exists(SURICATA_RULES_PATH):
                open(SURICATA_RULES_PATH, 'a').close()
                logger.info(f"Created rules file: {SURICATA_RULES_PATH}")
            
            # 규칙이 이미 존재하는지 확인
            with open(SURICATA_RULES_PATH, 'r') as f:
                if rule in f.read():
                    logger.info("Rule already exists, skipping")
                    return
            
            # 규칙 추가
            with open(SURICATA_RULES_PATH, 'a') as f:
                f.write(f"\n{rule}\n")
            
            logger.info(f"Rule added: {rule}")
            
            # Suricata 재로드 (Docker 환경에서는 PID가 다를 수 있음)
            try:
                # PID 파일에서 PID 읽기 (Docker 환경에 맞게 조정)
                if os.path.exists('/var/run/suricata.pid'):
                    with open('/var/run/suricata.pid', 'r') as f:
                        pid = f.read().strip()
                    # USR2 시그널 보내기
                    subprocess.run(['kill', '-USR2', pid], check=True)
                    logger.info(f"Sent reload signal to Suricata (PID: {pid})")
                else:
                    logger.warning("Suricata PID file not found, rules won't be reloaded")
            except Exception as e:
                logger.error(f"Suricata 재로드 중 오류: {e}")
            
        except Exception as e:
            logger.error(f"Suricata 규칙 추가 중 오류: {e}")
    
    def log_blocked_url(self, url, probability, event):
        """차단된 URL 로그 기록"""
        try:
            os.makedirs(os.path.dirname(BLOCK_LOG_FILE), exist_ok=True)
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'probability': probability,
                'src_ip': event.get('src_ip', ''),
                'dest_ip': event.get('dest_ip', ''),
                'user_agent': event.get('http', {}).get('http_user_agent', '')
            }
            
            with open(BLOCK_LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            logger.info(f"Blocked URL logged: {url}")
            
        except Exception as e:
            logger.error(f"차단 로그 작성 중 오류: {e}")

def main():
    """메인 실행 함수"""
    logger.info("Suricata 로그 모니터링 시작")
    
    # 필요한 디렉토리 생성
    os.makedirs(os.path.dirname(SURICATA_RULES_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(BLOCK_LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(SURICATA_EVE_LOG), exist_ok=True)
    
    # 로그 파일 감시 설정
    event_handler = SuricataLogHandler()
    observer = Observer()
    
    # EVE 로그 디렉토리가 존재하는지 확인
    eve_log_dir = os.path.dirname(SURICATA_EVE_LOG)
    if not os.path.exists(eve_log_dir):
        os.makedirs(eve_log_dir, exist_ok=True)
        logger.info(f"Created EVE log directory: {eve_log_dir}")
    
    observer.schedule(event_handler, path=os.path.dirname(SURICATA_EVE_LOG), recursive=False)
    observer.start()
    
    try:
        logger.info("Observer started, waiting for events...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Suricata 로그 모니터링 종료")
    
    observer.join()

if __name__ == '__main__':
    main()
