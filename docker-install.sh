#!/bin/bash
set -euo pipefail

echo "docker install"
sudo apt-get update -y
sudo apt-get install -y git jq vim curl

if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh ./get-docker.sh
    sudo systemctl start docker
    sudo systemctl enable docker
    rm -f get-docker.sh
    echo "docker install completed."
else
    echo "docker exists. skip..."
fi

echo "docker compose install"
DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
if ! docker compose version >/dev/null 2>&1; then
    mkdir -p "$DOCKER_CONFIG/cli-plugins"
    curl -SL "https://github.com/docker/compose/releases/download/latest/docker-compose-linux-x86_64" -o "$DOCKER_CONFIG/cli-plugins/docker-compose"
    chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
    echo "docker compose install completed."
    docker compose version
else
    echo "docker compose exists. skip..."
fi

echo "docker workspace path"
sudo mkdir -p /opt/docker
if [[ -n "${1:-}" ]]; then
    sudo chown -R "$1":"$1" /opt/docker/
fi
DOCKER_PATH=/opt/docker
echo "DOCKER PATH: ${DOCKER_PATH}"

echo "Tip: add user to docker group"
echo "# sudo usermod -aG docker <username>"
echo "# newgrp docker"