# Docker image for FACT_core
The `Dockerfile` provides an installation of all fact components (db, frontend,
backend).
To build the image run `make build`.
All other commands can be shown with `make help`.

Because FACT uses docker itselve, the docker socket from the host will be
passed to the container. This means that the use you run `make run` with needs
to have permissions to use docker.
The docker images that FACT requires can be build/pulled with `install.py
--backend-docker-images --frontend-docker-images`

## Environment variables
The Makefile uses the following environment variables.

`VERSION`: The version to be tagged when running `make build`

`IMAGE_NAME`: The name to be tagged when running `make build`

`CONTAINER_NAME`: The name of the container

`DOCKER_HOST`: Path to the docker socket. Default is `/var/run/docker.sock`

`FACT_CONFIG_DIR`: Path to the directory containing all config files for FACT.
Default is `../src/config`

`FACT_FW_DATA_PATH`: Path to the fact\_fw\_data directory on the host. Default
is /media/data/fact\_fw\_data/

`FACT_FW_DATA_GID`: Group of the `FACT_FW_DATA_PATH` directory. The group must
have rwx permissions. Default is `id -g`

`FACT_WT_MONGODB_PATH`: Path to the fact_t_mongodb directory on the host.
Default is /media/data/fact\_wt\_mongodb/

`FACT_WT_MONGODB_GID`: Group of the `FACT_WT_MONGODB_PATH` directory. The group
must have rwx permissions. Default is `id -g`
