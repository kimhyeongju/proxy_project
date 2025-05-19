from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
import re
from urllib.parse import urlparse
import math
from collections import Counter
import string
import logging
import os

# 로그 디렉토리 설정
LOG_DIR = os.environ.get('LOG_DIR', os.path.expanduser('~/url_classifier/logs'))
os.makedirs(LOG_DIR, exist_ok=True)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'flask_server.log'))
    ]
)
logger = logging.getLogger('url_classifier')

app = Flask(__name__)

model = None
model_path = os.path.join(os.getcwd(), 'model', 'catboost_url_model.cbm')

# 모델 로드 함수
def load_model():
    global model
    if model is None:
        try:
            model_path = os.path.join(os.getcwd(), 'model', 'catboost_url_model.cbm')
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"모델 파일을 찾을 수 없습니다: {model_path}")
            model = CatBoostClassifier()
            model.load_model(model_path)
            logger.info("CatBoost 모델 로드 성공")
        except Exception as e:
            logger.error(f"모델 로드 실패: {e}")
            raise
    return model

# URL 특성 추출 함수
def extract_url_features(url):
    features = {}
    try:
        # URL 길이
        features['url_length'] = len(url)
        
        # URL
        parsed_url = urlparse(url)
        
        # 경로 깊이
        features['path_depth'] = url.count('/')
        
        # 특수문자 수
        features['num_special_chars'] = sum(c in string.punctuation for c in url)
        
        # 특수문자 비율
        features['special_chars_ratio'] = features['num_special_chars'] / max(features['url_length'], 1)
        
        # 숫자 수
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # 숫자 비율
        features['digits_ratio'] = features['num_digits'] / max(features['url_length'], 1)
        
        # 대문자 수
        features['num_uppercase'] = sum(c.isupper() for c in url)
        
        # 대문자 비율
        features['uppercase_ratio'] = features['num_uppercase'] / max(features['url_length'], 1)
        
        # 서브도메인 수
        if parsed_url.netloc:
            subdomain_parts = parsed_url.netloc.split('.')[:-2]
            features['subdomain_count'] = len(subdomain_parts) if subdomain_parts else 0
        else:
            features['subdomain_count'] = 0
        
        # URL Shannon 엔트로피 계산 함수
        def entropy(string_value):
            counter = Counter(string_value)
            length = len(string_value)
            if length <= 1:
                return 0
            return -sum((count / length) * math.log2(count / length) for count in counter.values())
        
        # URL 엔트로피
        features['url_entropy'] = entropy(url)
        
        # 하이픈 수
        features['hyphen_count'] = url.count('-')
        
        # suspicious_tld (의심스러운 최상위 도메인)
        suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site', 'info', 'biz', 'cn', 'ru', 'tk']
        tld = parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else ''
        features['suspicious_tld'] = 1 if tld.lower() in suspicious_tlds else 0
        
        # login 키워드 포함 여부
        features['has_login'] = 1 if 'login' in url.lower() else 0
        
    except Exception as e:
        logger.error(f"특성 추출 중 오류: {e}")
        # 기본값으로 채우기
        for key in ['url_length', 'path_depth', 'num_special_chars', 'special_chars_ratio',
                   'num_digits', 'digits_ratio', 'num_uppercase', 'uppercase_ratio',
                   'subdomain_count', 'url_entropy', 'hyphen_count', 'suspicious_tld', 'has_login']:
            if key not in features:
                features[key] = 0
    
    return features

# API 상태 확인
@app.route('/health', methods=['GET'])
def health_check():
    try:
        if model is None:
            load_model()
        return jsonify({'status': 'healthy', 'model_loaded': model is not None})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# URL 예측
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # 모델이 로드되지 않았다면 로드
        if model is None:
            load_model()
        
        # 요청 데이터 가져오기
        data = request.get_json(force=True)
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL이 제공되지 않았습니다.'}), 400
        
        # URL 특성 추출
        features = extract_url_features(url)
        
        # 모델 입력을 위한 데이터프레임 생성
        df = pd.DataFrame([features])
        
        # 필요한 특성만 선택 및 순서 맞추기
        required_features = [
            'url_entropy', 'num_special_chars', 'url_length', 'path_depth', 
            'digits_ratio', 'num_digits', 'subdomain_count', 'special_chars_ratio',
            'hyphen_count', 'suspicious_tld', 'num_uppercase', 'uppercase_ratio', 
            'has_login'
        ]
        
        # 누락된 특성에 대해 0 값 채우기
        for feature in required_features:
            if feature not in df.columns:
                df[feature] = 0
        
        # 모델 입력 순서에 맞게 재정렬
        df = df[required_features]
        
        # 예측
        prediction = model.predict_proba(df)[0, 1]  # 악성 URL일 확률
        is_malicious = prediction > 0.5  # 임계값 0.5
        
        # 로깅
        logger.info(f"URL 분석: {url} - 악성 확률: {prediction:.4f}")
        
        # 결과 반환
        result = {
            'url': url,
            'is_malicious': bool(is_malicious),
            'probability': float(prediction),
            'features': features
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"예측 중 오류: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    try:
        load_model()
        logger.info("Flask 애플리케이션 시작")
    except Exception as e:
        logger.error(f"애플리케이션 시작 실패: {e}")
        exit(1)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
