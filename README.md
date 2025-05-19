## 🙌 READ ME!
![image](https://github.com/user-attachments/assets/783ff7c0-aaa5-41f4-ba4b-2cf9b7b4243d)

<br>

## ❓ 개요  
- **개발 환경** :   Ubuntu 18.04
- **Python 버전** : 3.10 (conda 가상 환경 사용)
- **Working directory** : /home/khj/url_classifier
- **모델 파일 이름** : catboost_url_model.cbm

## 🙋‍♀️ Docker 설치하기   
```bash
$ sudo apt update
$ sudo apt install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common

$ su root
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
OK
$ add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
$ cat /etc/apt/sources.list # 리포지토리 추가된 거 확인

$ apt update
$ apt -y install docker-ce docker-ce-cli containerd.io

$ sudo su -
$ nano /etc/docker/daemon.json
# 아래 내용 입력
{
    "exec-opts" : ["native.cgroupdriver=systemd"],
    "log-driver" : "json-file",
    "log-opts" : {"max-size" : "100m"},
    "storage-driver" : "overlay2"
}

$ mkdir -p /etc/systemd/system/docker.service.d
$ systemctl daemon-reload
$ systemctl enable docker.service
$ systemctl restart docker
$ systemctl status docker.service
```
<br>

## 🛠 디렉터리 생성 및 prod 도커 컴포즈 파일 생성
1. `$ git clone ` 
2. `$ cd `   
3. `$ sudo chmod +x setup.sh`
4. `$ setup.sh`
5.  ` `
