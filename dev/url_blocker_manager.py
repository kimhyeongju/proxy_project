#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import time
import logging
from datetime import datetime, timedelta
from collections import Counter
import argparse

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('url_blocker_manager')

# 설정 파일 경로
HOME_DIR = os.path.expanduser('~')
CONFIG_FILE = os.path.join(HOME_DIR, 'url_classifier', 'config.json')


# 기본 설정
DEFAULT_CONFIG = {
    'flask_server': {
        'host': 'localhost',
        'port': 5000,
        'log_file': os.path.join(HOME_DIR, 'url_classifier', 'logs', 'flask_server.log')
    },
    'proxy_server': {
        'host': '0.0.0.0',
        'port': 8888,
        'log_file': os.path.join(HOME_DIR, 'url_classifier', 'logs', 'proxy_server.log')
    },
    'suricata': {
        'rules_path': '/etc/suricata/rules/malicious_urls.rules',
        'log_path': '/var/log/suricata/eve.json'
    },
    'blocked_urls_log': os.path.join(HOME_DIR, 'url_classifier', 'logs', 'blocked_urls.log')
}

class URLBlockerManager:
    def __init__(self):
        self.config = self.load_config()
        self.ensure_directories()
    
    def load_config(self):
        """설정 파일 로드"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        else:
            # 기본 설정 사용
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
            return DEFAULT_CONFIG
    
    def ensure_directories(self):
        """필요한 디렉토리 생성"""
        dirs = [
            os.path.join(HOME_DIR, 'url_classifier', 'logs'),
            os.path.dirname(CONFIG_FILE),
            os.path.dirname(self.config['suricata']['rules_path'])
    ]
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
    
    def start_services(self):
        """모든 서비스 시작"""
        logger.info("URL Blocker 서비스 시작")
        
        # Flask 서버 시작
        flask_cmd = f"python3 app.py > {self.config['flask_server']['log_file']} 2>&1 &"
        subprocess.Popen(flask_cmd, shell=True)
        logger.info("Flask 서버 시작됨")
        
        time.sleep(2)  # Flask 서버 시작 대기
        
        # 프록시 서버 시작
        proxy_cmd = f"python3 proxy_server.py --host {self.config['proxy_server']['host']} --port {self.config['proxy_server']['port']} > {self.config['proxy_server']['log_file']} 2>&1 &"
        subprocess.Popen(proxy_cmd, shell=True)
        logger.info("프록시 서버 시작됨")
        
        # Suricata 모니터 시작
        monitor_cmd = "python3 suricata_monitor.py > /var/log/url_blocker/suricata_monitor.log 2>&1 &"
        subprocess.Popen(monitor_cmd, shell=True)
        logger.info("Suricata 모니터 시작됨")
        
        logger.info("모든 서비스가 시작되었습니다.")
    
    def stop_services(self):
        """모든 서비스 중지"""
        logger.info("URL Blocker 서비스 중지")
        
        # Python 프로세스 종료
        processes = ['app.py', 'proxy_server.py', 'suricata_monitor.py']
        for process in processes:
            try:
                subprocess.run(['pkill', '-f', process], check=True)
                logger.info(f"{process} 중지됨")
            except subprocess.CalledProcessError:
                logger.warning(f"{process} 프로세스를 찾을 수 없음")
        
        logger.info("모든 서비스가 중지되었습니다.")
    
    def restart_services(self):
        """모든 서비스 재시작"""
        self.stop_services()
        time.sleep(2)
        self.start_services()
    
    def status(self):
        """서비스 상태 확인"""
        print("\n=== URL Blocker 서비스 상태 ===")
        
        # 프로세스 상태 확인
        processes = {
            'Flask 서버': 'app.py',
            '프록시 서버': 'proxy_server.py',
            'Suricata 모니터': 'suricata_monitor.py'
        }
        
        for name, process in processes.items():
            result = subprocess.run(['pgrep', '-f', process], capture_output=True)
            if result.returncode == 0:
                print(f"✓ {name}: 실행 중 (PID: {result.stdout.decode().strip()})")
            else:
                print(f"✗ {name}: 중지됨")
        
        # Suricata 상태
        result = subprocess.run(['systemctl', 'is-active', 'suricata'], capture_output=True)
        if result.stdout.decode().strip() == 'active':
            print("✓ Suricata: 실행 중")
        else:
            print("✗ Suricata: 중지됨")
        
        # 통계 정보
        self.show_statistics()
    
    def show_statistics(self):
        """차단 통계 표시"""
        print("\n=== 차단 통계 ===")
        
        blocked_log = self.config['blocked_urls_log']
        if not os.path.exists(blocked_log):
            print("차단된 URL이 없습니다.")
            return
        
        blocked_urls = []
        with open(blocked_log, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    blocked_urls.append(entry)
                except:
                    continue
        
        if not blocked_urls:
            print("차단된 URL이 없습니다.")
            return
        
        # 전체 차단 수
        print(f"총 차단 수: {len(blocked_urls)}")
        
        # 최근 24시간 차단 수
        now = datetime.now()
        recent_blocks = [url for url in blocked_urls 
                        if datetime.fromisoformat(url['timestamp']) > now - timedelta(days=1)]
        print(f"최근 24시간 차단 수: {len(recent_blocks)}")
        
        # 가장 많이 차단된 도메인
        domains = []
        for url in blocked_urls:
            try:
                domain = url['url'].split('/')[2]
                domains.append(domain)
            except:
                continue
        
        domain_counter = Counter(domains)
        print("\n가장 많이 차단된 도메인:")
        for domain, count in domain_counter.most_common(5):
            print(f"  - {domain}: {count}회")
    
    def setup_firefox_proxy(self):
        """Firefox 프록시 설정 가이드"""
        print("\n=== Firefox 프록시 설정 가이드 ===")
        print("1. Firefox 설정 > 네트워크 설정으로 이동")
        print("2. '수동 프록시 설정' 선택")
        print("3. HTTP 프록시 설정:")
        print(f"   - HTTP 프록시: {self.config['proxy_server']['host']}")
        print(f"   - 포트: {self.config['proxy_server']['port']}")
        print("4. 'HTTPS에도 이 프록시 서버 사용' 체크")
        print("5. 저장")
    
    def tail_logs(self, service='all'):
        """로그 파일 실시간 확인"""
        log_files = {
            'flask': self.config['flask_server']['log_file'],
            'proxy': self.config['proxy_server']['log_file'],
            'monitor': '/var/log/url_blocker/suricata_monitor.log',
            'blocked': self.config['blocked_urls_log']
        }
        
        if service == 'all':
            files = ' '.join(log_files.values())
        else:
            files = log_files.get(service, '')
        
        if files:
            subprocess.run(f"tail -f {files}", shell=True)
        else:
            print(f"알 수 없는 서비스: {service}")

def main():
    parser = argparse.ArgumentParser(description='URL Blocker 시스템 관리')
    parser.add_argument('command', choices=['start', 'stop', 'restart', 'status', 'logs', 'setup'],
                       help='실행할 명령')
    parser.add_argument('--service', default='all', help='대상 서비스 (logs 명령어와 함께 사용)')
    
    args = parser.parse_args()
    
    manager = URLBlockerManager()
    
    if args.command == 'start':
        manager.start_services()
    elif args.command == 'stop':
        manager.stop_services()
    elif args.command == 'restart':
        manager.restart_services()
    elif args.command == 'status':
        manager.status()
    elif args.command == 'logs':
        manager.tail_logs(args.service)
    elif args.command == 'setup':
        manager.setup_firefox_proxy()

if __name__ == '__main__':
    main()
