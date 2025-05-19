echo "Stop all services..."
python3 url_blocker_manager.py stop 2>/dev/null
pkill -f app.py
pkill -f proxy_server.py
pkill -f suricata_monitor.py
sleep 2

echo "delete log files..."
rm -rf ~/url_classifier/logs/*
rm -f ~/url_classifier/url_classifier.log
rm -f ~/url_classifier/*.log

sudo rm -rf /var/log/url_blocker/*
sudo rm -f /var/log/suricata/eve.json
sudo rm -f /var/log/suricata/*.log

echo "Initialize Suricata rules..."
sudo systemctl stop suricata
sudo truncate -s 0 /etc/suricata/rules/malicious_urls.rules 2>/dev/null || {
    sudo rm -f /etc/suricata/rules/malicious_urls.rules
    sudo touch /etc/suricata/rules/malicious_urls.rules
    sudo chmod 666 /etc/suricata/rules/malicious_urls.rules
}


echo "Delete configure files..."
rm -f ~/url_classifier/config.json
sudo rm -f /etc/url_blocker/config.json


echo "Delete python cache..."
find ~/url_classifier -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
find ~/url_classifier -name "*.pyc" -delete 2>/dev/null


echo "Re-create directories..."
mkdir -p ~/url_classifier/logs
sudo mkdir -p /var/log/url_blocker
sudo chown -R $USER:$USER /var/log/url_blocker


echo "Restart Suricata..."
sudo systemctl restart suricata

echo ""
echo "=== Initialize complete ==="
echo "Run:"
echo "python3 url_blocker_manager.py start"
