#!/bin/bash
echo "docker install"
sudo apt-get install git jq vim curl

if [[ -z $(command -v docker) ]]; then
    curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh ./get-docker.sh
    sudo systemctl start docker && systemctl enable docker
    echo "docker install completed."
else
    echo "docker exists. skip..."
fi

echo "docker compose install"
DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
if [[ -z $(command -v docker compose) ]]; then
    mkdir -p $DOCKER_CONFIG/cli-plugins
    curl -SL https://github.com/docker/compose/releases/download/latest/docker-compose-linux-x86_64 -o $DOCKER_CONFIG/cli-plugins/docker-compose
    chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose
    ln -s $DOCKER_CONFIG/cli-plugins/docker-compose /usr/local/lib/
    echo "docker compose install completed."
    docker compose version
else
    echo "docker compose exists. skip..."
fi
echo "docker compose install"
sudo mkdir -p /opt/docker
sudo chown -R $1 /opt/docker/
DOCKER_PATH=/opt/docker
echo "DOCKER PATH: ${DOCKER_PATH}"

echo "TODO: add $1 to docker group"
echo "# sudo newgrp docker"
echo "# usermod -aG docker $1"
