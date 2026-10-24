#!/usr/bin/env bash
# "Quick server setup" as pasted from an AI answer.
set -e

curl -fsSL https://get.example-tool.sh | sudo bash
sudo apt-get install -y nginx
sudo ufw disable
chmod -R 777 /var/www

export DB_PASSWORD=Sup3rS3cret!
az vm create -g rg-demo -n vm-demo --image Ubuntu2204 --admin-username azureuser --admin-password "Sup3rS3cret!2026"
az vm open-port -g rg-demo -n vm-demo --port 22

BUILD_DIR=$1
rm -rf "$BUILD_DIR"/*
python3 -m http.server 8000
