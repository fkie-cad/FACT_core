VERSION ?= latest
IMAGE_NAME ?= fkiecad/fact
CONTAINER_NAME ?= fact

DOCKER_HOST ?= /var/run/docker.sock

# Default to the config contained in this repo
FACT_CONFIG_DIR ?= $(shell realpath $(shell dirname $(MAKEFILE_LIST)))/../src/config
FACT_DOCKER_DIR ?= /tmp

FACT_FW_DATA_PATH ?= /media/data/fact_fw_data/
FACT_FW_DATA_GID ?= $(shell id -g)
FACT_WT_MONGODB_PATH ?= /media/data/fact_wt_mongodb/
FACT_WT_MONGODB_GID ?= $(shell id -g)

# Auto generate a help page from comments after the targets
# https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the container
	docker build --rm -t $(IMAGE_NAME) .

pull: ## Pull or build all neccessary docker containers required to run FACT
	docker run \
		--rm \
		-it \
		--group-add $(getent group docker | cut -d: -f3) \
		-v $(DOCKER_HOST):/var/run/docker.sock \
		fkiecad/fact pull-containers

run: ## Run container
	# --group-add is needed to give the user inside the container
	# permission to read&write to the docker socket

	touch $(FACT_WT_MONGODB_PATH)/REINITIALIZE_DB

	docker run \
		-it \
		--name $(CONTAINER_NAME) \
		--hostname $(CONTAINER_NAME) \
		--group-add $(shell getent group docker | cut -d: -f3) \
		-v $(DOCKER_HOST):/var/run/docker.sock \
		--mount type=bind,source=$(FACT_CONFIG_DIR),destination=/opt/FACT_core/src/config/ \
		--group-add $(FACT_FW_DATA_GID) \
		-v $(FACT_FW_DATA_PATH):/media/data/fact_fw_data/ \
		--group-add $(FACT_WT_MONGODB_GID) \
		-v $(FACT_WT_MONGODB_PATH):/media/data/fact_wt_mongodb/ \
		-v $(FACT_DOCKER_DIR):$(FACT_DOCKER_DIR) \
		-p 5000:5000 \
		$(IMAGE_NAME):$(VERSION) start

start: ## Start container
	docker start -i $(CONTAINER_NAME)

stop: ## Stop a running container
	docker stop $(CONTAINER_NAME)

remove: ## Remove the container
	docker rm $(CONTAINER_NAME)
