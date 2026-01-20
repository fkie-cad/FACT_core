#!/usr/bin/env bash

set -eux

# start docker service
dockerd &

# redis runs in a different container => replace "localhost" with "redis"
sed -i 's/host = "localhost"/host = "redis"/g' /opt/fact/config/fact-core-config.toml
# postgres also runs in a different container => replace "localhost" with "db"
sed -i 's/server = "localhost"/server = "db"/g' /opt/fact/config/fact-core-config.toml
# replace localhost with 0.0.0.0 in uWSGI config so that the frontend can be reached from outside
sed -i 's/127.0.0.1/0.0.0.0/g' /opt/fact/config/uwsgi_config.ini

# init the DB
python3 init_postgres.py

python3 start_fact_frontend.py --no-radare
