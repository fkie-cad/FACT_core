#!/bin/sh

if [ "$1" = "init_database" ] ; then
    python3 /opt/FACT_core/src/init_database.py
fi

shift 1

exec /opt/FACT_core/start_all_installed_fact_components "$@"
