#!/bin/bash


case "$1" in
    "start")
        shift 1
        # TODO this path could be configurable
        # It is not really necessary to make it configurable since there is no
        # usecase to change the database path inside the docker container
        if [ -e /media/data/fact_wt_mongodb/REINITIALIZE_DB ]; then
            python3 /opt/FACT_core/src/init_database.py && \
                rm /media/data/fact_wt_mongodb/REINITIALIZE_DB
        fi
        exec /opt/FACT_core/start_all_installed_fact_components "$@"
    ;;
    "pull-containers")
        # We cant to this in the Dockerfile, because the docker socket is not shared to there
        exec /opt/FACT_core/src/install.py \
            --backend-docker-images \
            --frontend-docker-images
    ;;
    *)
        printf "See https://github.com/fkie-cad/FACT_core/blob/master/docker/README.md for how to start this container\n"
        exit 0
esac
