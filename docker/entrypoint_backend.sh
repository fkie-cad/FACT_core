#!/usr/bin/env bash

set -eux

# start docker service
dockerd &

# redis runs in a different container => replace "localhost" with "redis"
sed -i 's/host = "localhost"/host = "redis"/g' /opt/fact/config/fact-core-config.toml
# postgres also runs in a different container => replace "localhost" with "db"
sed -i 's/server = "localhost"/server = "db"/g' /opt/fact/config/fact-core-config.toml

if [ -e DOCKER_INSTALL_INCOMPLETE ]; then
  echo "Installing FACT docker images..."
  python3 install.py --backend-docker-images
  rm DOCKER_INSTALL_INCOMPLETE
  echo "FACT docker image installation completed"
fi

# We can't use rest/status here, because it needs the list of available plugins (which is available after the backend
# was started).
until curl -s -X GET 'http://frontend:5000/rest/statistics/general'; do
    echo "Waiting for FACT frontend to start..."
    sleep 2
done
echo "FACT frontend is ready"

python3 start_fact_backend.py
