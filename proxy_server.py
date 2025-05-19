#!/usr/bin/env python3
import asyncio
import aiohttp
from aiohttp import web
import json
import requests
import logging
import ssl
import re
from urllib.parse import urlparse
from datetime import datetime
import os
import argparse

# 로그 디렉토리 설정
LOG_DIR = os.environ.get('LOG_DIR', os.path.expanduser('~/url_classifier/logs'))

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'proxy_server.log'))
    ]
)
logger = logging.getLogger('proxy_server')

# Flask 서버 URL(환경 변수로부터 가져옴)
FLASK_SERVER_URL = os.environ.get('FLASK_SERVER_URL', 'http://localhost:5000/predict')

# 화이트리스트 도메인 (차단하지 않을 도메인)
WHITELIST_DOMAINS = [
    # 시스템 연결성 확인
    'connectivity-check.ubuntu.com',
    'detectportal.firefox.com',
    'captive.apple.com',
    'connectivitycheck.gstatic.com',
    'msftconnecttest.com',
    'www.msftconnecttest.com',
    
    # SSL 인증서 검증 (OCSP)
    'ocsp.sectigo.com',
    'ocsp.digicert.com',
    'ocsp.pki.goog',
    'ocsp.verisign.com',
    'ocsp.entrust.net',
    'ocsp.comodoca.com',
    'ocsp.godaddy.com',
    'ocsp.globalsign.com',
    'ocsp.usertrust.com',
    
    # CDN 및 업데이트 서버
    'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com',
    'unpkg.com',
    'update.googleapis.com',
    'safebrowsing.googleapis.com',
    
    # 필수 서비스
    'accounts.google.com',
    'api.github.com',
    'auth.docker.io',
    'registry.npmjs.org',
    'pypi.org',
    
    # 한국 주요 포털 및 서비스
    'daum.net',
    'www.daum.net',
    'naver.com',
    'www.naver.com',
    'kakao.com',
    'www.kakao.com',
    'tistory.com',
    'www.tistory.com',
    'nate.com',
    'www.nate.com',
    
    # 한국 주요 뉴스 사이트
    'chosun.com',
    'www.chosun.com',
    'donga.com',
    'www.donga.com',
    'joins.com',
    'www.joins.com',
    'hankyung.com',
    'www.hankyung.com',
    'mk.co.kr',
    'www.mk.co.kr',
    'yonhapnews.co.kr',
    'www.yonhapnews.co.kr',
    
    # 한국 정부 및 공공기관
    'korea.kr',
    'www.korea.kr',
    'go.kr',
    'www.go.kr',
    
    # 한국 주요 쇼핑몰
    'coupang.com',
    'www.coupang.com',
    'gmarket.co.kr',
    'www.gmarket.co.kr',
    '11st.co.kr',
    'www.11st.co.kr',
    'ssg.com',
    'www.ssg.com',
    
    # 추가 허용 도메인 (필요시 추가)
    'localhost',
    '127.0.0.1'
]

# 차단 페이지 HTML (수정된 버전)
BLOCKED_PAGE_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>접근 차단됨</title>
    <style type="text/css">
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background-color: #f5f5f5;
            margin: 0;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .warning {{
            color: #d32f2f;
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .info {{
            margin-top: 20px;
            text-align: left;
            background-color: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
        }}
        .info p {{
            margin: 10px 0;
        }}
        .info strong {{
            color: #333;
        }}
        .icon {{
            font-size: 48px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1 class="warning">악성 URL 차단</h1>
        <p>요청하신 URL은 악성 사이트로 분류되어 접근이 차단되었습니다.</p>
        <div class="info">
            <p><strong>차단된 URL:</strong> {url}</p>
            <p><strong>위험도:</strong> {probability:.1%}</p>
            <p><strong>차단 시각:</strong> {timestamp}</p>
        </div>
    </div>
</body>
</html>"""

class URLProxyServer:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.setup_routes()
        
    def setup_routes(self):
        # 라우트 설정
        self.app.router.add_route('*', '/{path:.*}', self.handle_request)

    # URL이 화이트리스트에 있는지 확인하는 함수
    def is_whitelisted(self, url):
        
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.lower()
            
            # 호스트명에서 포트 제거
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            for whitelist_domain in WHITELIST_DOMAINS:
                if hostname == whitelist_domain or hostname.endswith('.' + whitelist_domain):
                    logger.info(f"화이트리스트 도메인: {hostname}")
                    return True
            
            return False
        except Exception as e:
            logger.error(f"화이트리스트 확인 중 오류: {e}")
            return False
    
    # 모든 HTTP 요청 처리 비동기 함수
    async def handle_request(self, request):
        try:
            # 디버그 로그
            logger.info(f"요청 메서드: {request.method}")
            logger.info(f"요청 헤더: {dict(request.headers)}")
            
            # CONNECT 메서드 처리 (HTTPS 프록시)
            if request.method == 'CONNECT':
                logger.info("CONNECT 메서드 감지 - HTTPS 터널링")
                return await self.handle_connect(request)
            
            # 요청 URL 구성
            if request.host:
                if request.scheme:
                    url = f"{request.scheme}://{request.host}{request.path_qs}"
                else:
                    # 프록시 요청에서 스키마가 없을 수 있음
                    url = f"http://{request.host}{request.path_qs}"
            elif str(request.url).startswith('http'):
                url = str(request.url)
            else:
                logger.error(f"잘못된 요청: {request}")
                return web.Response(text="Invalid request", status=400)
            
            logger.info(f"요청 URL: {url}")
            
            # 화이트리스트 확인
            if self.is_whitelisted(url):
                logger.info(f"화이트리스트 URL 통과: {url}")
                return await self.forward_request(request)
            
            # URL 검사
            is_malicious, probability = await self.check_url(url)
            logger.info(f"URL 검사 결과 - 악성: {is_malicious}, 확률: {probability:.4f}")
            
            if is_malicious:
                # 악성 URL인 경우 차단 페이지 반환
                logger.warning(f"악성 URL 차단됨: {url} - 확률: {probability:.4f}")

                blocked_log_file = os.path.join(LOG_DIR, 'blocked_urls.log')
                blocked_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'url': url,
                    'probability': probability,
                    'source_ip': request.remote,
                    'user_agent': request.headers.get('User-Agent', '')
                }
    
                with open(blocked_log_file, 'a') as f:
                    f.write(json.dumps(blocked_entry) + '\n')
                
                # HTML 생성 시 timestamp 추가
                blocked_html = BLOCKED_PAGE_HTML.format(
                    url=url, 
                    probability=probability,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
                
                # 응답 헤더 설정
                headers = {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
                
                return web.Response(
                    text=blocked_html,
                    status=403,
                    headers=headers
                )
            
            # 정상 URL인 경우 실제 요청 전달
            logger.info(f"정상 URL 전달: {url}")
            return await self.forward_request(request)
            
        except Exception as e:
            logger.error(f"요청 처리 중 오류: {e}", exc_info=True)
            return web.Response(text=f"Error: {str(e)}", status=500)
    
    async def handle_connect(self, request):
        """HTTPS CONNECT 메서드 처리"""
        try:
            # CONNECT 요청에서 대상 호스트 추출
            host, port = request.path_qs.split(':')
            port = int(port)
            
            logger.info(f"CONNECT 터널 요청: {host}:{port}")
            
            # 화이트리스트 확인
            if self.is_whitelisted(f"https://{host}"):
                logger.info(f"화이트리스트 HTTPS 사이트: {host}")
            else:
                # URL 검사 (HTTPS URL로 구성)
                https_url = f"https://{host}/"
                is_malicious, probability = await self.check_url(https_url)
                
                if is_malicious:
                    logger.warning(f"악성 HTTPS 사이트 차단: {host}")
                    return web.Response(text="Forbidden", status=403)
            
            # 터널링을 위한 응답
            return web.Response(status=200, reason='Connection Established')
            
        except Exception as e:
            logger.error(f"CONNECT 처리 중 오류: {e}")
            return web.Response(text="Bad Gateway", status=502)
    
    # URL을 검사하여 악성 여부 확인하는 비동기 함수
    async def check_url(self, url):
        try:
            # 원본 URL 저장
            original_url = url
            
            # URL 정규화 - http://, https:// 제거하여 검사
            normalized_url = url
            if url.startswith('http://'):
                normalized_url = url[7:]  # http:// 제거
            elif url.startswith('https://'):
                normalized_url = url[8:]  # https:// 제거
            
            # 후행 슬래시 제거
            if normalized_url.endswith('/'):
                normalized_url = normalized_url[:-1]
            
            logger.info(f"Flask 서버로 URL 검사 요청: {normalized_url}")
            
            # Flask 서버에 정규화된 URL로 분류 요청
            async with aiohttp.ClientSession() as session:
                async with session.post(FLASK_SERVER_URL, 
                                    json={'url': normalized_url}, 
                                    timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Flask 서버 응답: {result}")
                        return result.get('is_malicious', False), result.get('probability', 0.0)
                    else:
                        logger.error(f"Flask 서버 오류: {response.status}")
                        logger.error(f"응답 내용: {await response.text()}")
            
            return False, 0.0
            
        except aiohttp.ClientConnectorError:
            logger.error(f"Flask 서버에 연결할 수 없습니다: {FLASK_SERVER_URL}")
            return False, 0.0
        except Exception as e:
            logger.error(f"URL 검사 중 오류: {e}", exc_info=True)
            # 오류 발생 시 안전을 위해 통과
            return False, 0.0
    
    # 웹사이트로 요청을 전달하는 비동기 함수
    async def forward_request(self, request):
        try:
            # 원본 요청 헤더 복사
            headers = dict(request.headers)
            headers.pop('Host', None)
            headers.pop('Proxy-Connection', None)
            
            # 원본 URL 구성
            if 'Host' in request.headers:
                host = request.headers['Host']
                # 프록시 URL에서 실제 URL로 변환
                if request.scheme == 'http':
                    url = f"http://{host}{request.path_qs}"
                else:
                    url = f"https://{host}{request.path_qs}"
            else:
                # 요청 URL 직접 사용
                url = str(request.url)
                
            logger.info(f"요청 전달: {url}")
            
            # SSL 컨텍스트 생성 (HTTPS 용)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # 요청 전달
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=await request.read(),
                    allow_redirects=False
                ) as response:
                    # 응답 본문 읽기
                    body = await response.read()
                    
                    # 응답 헤더 복사
                    response_headers = dict(response.headers)
                    response_headers.pop('Content-Encoding', None)
                    response_headers.pop('Transfer-Encoding', None)
                    response_headers.pop('Connection', None)
                    
                    return web.Response(
                        body=body,
                        status=response.status,
                        headers=response_headers
                    )
                    
        except Exception as e:
            logger.error(f"요청 전달 중 오류: {e}")
            return web.Response(text=f"Proxy Error: {str(e)}", status=502)
    
    def run(self):
        """프록시 서버 실행"""
        logger.info(f"URL 프록시 서버 시작 - {self.host}:{self.port}")
        web.run_app(self.app, host=self.host, port=self.port)

def main():
    parser = argparse.ArgumentParser(description='URL 프록시 서버')
    parser.add_argument('--host', default='0.0.0.0', help='호스트 주소')
    parser.add_argument('--port', type=int, default=8888, help='포트 번호')
    args = parser.parse_args()

    proxy = URLProxyServer(host=args.host, port=args.port)
    proxy.run()

if __name__ == '__main__':
    main()
