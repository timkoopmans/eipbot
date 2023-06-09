.PHONY: list
SHELL := /bin/bash
export DOCKER_BUILDKIT=1

list:
	@awk -F: '/^[A-z]/ {print $$1}' Makefile | sort

_ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

build:
	docker compose build

deploy:
	kubectl apply -f eipbot.yml

replace:
	kubectl get pod eipbot -o yaml | kubectl replace --force -f -
	kubectl get pod eipbot-slack -o yaml | kubectl replace --force -f -
