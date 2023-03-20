.PHONY: list
SHELL := /bin/bash
export DOCKER_BUILDKIT=1

list:
	@awk -F: '/^[A-z]/ {print $$1}' Makefile | sort

_ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

build:
	docker compose build

deploy:
	kubectl apply -f eipbot.yaml