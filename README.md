## 🙌 READ ME!
![image](https://github.com/user-attachments/assets/783ff7c0-aaa5-41f4-ba4b-2cf9b7b4243d)
<br>

## ❓ 개요  
- **개발 환경** :   Ubuntu 18.04
- **프록시 서버 IP** : 192.168.100.134
- **Python 버전** : 3.10 (conda 가상 환경 사용)
- **Docker 버전** : 24.0.2
- **Working directory** : /home/khj/url_classifier
- **모델 파일 이름** : catboost_url_model.cbm
<br>

## 🐳 Docker 설치 
```bash
$ sudo su
$ apt-get update
$ apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common

$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
OK
$ add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
$ cat /etc/apt/sources.list # 리포지토리 추가된 거 확인

$ apt-get update
$ apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose

$ nano /etc/docker/daemon.json
# 아래 내용 입력
{
    "exec-opts" : ["native.cgroupdriver=systemd"],
    "log-driver" : "json-file",
    "log-opts" : {"max-size" : "100m"},
    "storage-driver" : "overlay2"
}

$ systemctl daemon-reload
$ systemctl enable docker.service
$ systemctl start docker
$ systemctl status docker.service
```
<br>

## 📂 디렉터리 생성 및 prod 도커 컴포즈 파일 생성
```bash
$ git clone https://github.com/kimhyeongju/proxy_project.git
$ cd proxy_project/
$ ./setup.sh
```
<br>

## 🤗 허깅페이스에서 학습된 모델 다운로드
```bash
$ cd model/
$ wget https://huggingface.co/userzhu/URL_classifier/resolve/main/catboost_url_model.cbm
```
<br>

## 🛠 도커 컴포즈 빌드
```bash
$ cd ..
$ docker-compose -f docker-compose.prod.yml up -d
$ docker-compose -f docker-compose.prod.yml ps
```
<br>

## 🔎상태 확인
```bash
$ curl http://localhost:5000/health
{"model_loaded":true,"status":"healthy"}
```

## 📃 로그 확인
```bash
# Flask 서버 로그 확인
cat ./logs/flask_server.log

# 프록시 서버 로그 확인
cat ./logs/proxy_server.log
```


