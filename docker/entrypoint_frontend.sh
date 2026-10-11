#!/usr/bin/env bash

set -eux

# start docker service
dockerd &

# redis runs in a different container => replace "localhost" with "redis"
sed -i '/^\[common\.redis\]/,/^\[/{ /host = "localhost"/s//host = "redis"/ }' /opt/fact/config/fact-core-config.toml
# postgres also runs in a different container => replace "localhost" with "db"
sed -i 's/server = "localhost"/server = "db"/g' /opt/fact/config/fact-core-config.toml
# switch to correct hasura host/port
sed -i '/^\[frontend\.hasura\]/,/^\[/{ /host = "localhost"/s//host = "hasura"/ }' /opt/fact/config/fact-core-config.toml
sed -i '/^\[frontend\.hasura\]/,/^\[/{ /port = 33333/s//port = 8080/ }' /opt/fact/config/fact-core-config.toml
# replace localhost with 0.0.0.0 in uWSGI config so that the frontend can be reached from outside
sed -i 's/127.0.0.1/0.0.0.0/g' /opt/fact/config/uwsgi_config.ini

# init the DB
python3 init_postgres.py

# init hasura
python3 storage/graphql/hasura/init_hasura.py

python3 start_fact_frontend.py --no-radare
