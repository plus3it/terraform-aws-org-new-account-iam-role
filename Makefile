SHELL := /bin/bash
export PYTHONPATH := $(PYTHONPATH):./lambda/src

include $(shell test -f .tardigrade-ci || curl -sSL -o .tardigrade-ci "https://raw.githubusercontent.com/plus3it/tardigrade-ci/master/bootstrap/Makefile.bootstrap"; echo .tardigrade-ci)

pytest/install:
	@ $(MAKE) install/pip/$(@D) PYPI_PKG_NAME=$(@D)
	@ python -m pip install -r lambda/tests/requirements_dev.txt

.PHONY: python/deps
python/deps:
	@ echo "[$@] Installing package dependencies"
	@ python -m pip install -r lambda/src/requirements.txt

.PHONY: python/test
python/test: | guard/program/pytest
python/test:
	@ echo "[$@] Starting Python tests"
	pytest lambda/tests
	@ echo "[$@]: Tests executed!"

.PHONY: localstack/terratest localstack/up localstack/down localstack/clean
localstack/terratest: | guard/program/terraform guard/program/go
	@ echo "[$@] Running Terraform tests against LocalStack"
	DOCKER_RUN_FLAGS="--network host --rm" \
		$(MAKE) docker/run target=terratest/test
	@ echo "[$@]: Completed successfully!"

localstack/up: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Starting LocalStack"
	docker-compose -f tests/docker-compose-localstack.yml up --detach

localstack/down: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Stopping and removing LocalStack container"
	docker-compose -f tests/docker-compose-localstack.yml down

localstack/clean: | localstack/down
	@ echo "[$@] Stopping and removing LocalStack container and images"
	set +o pipefail; docker images | grep lambci | \
		awk '{print $$1 ":" $$2}' | xargs -r docker rmi
	set +o pipefail; docker images | grep new-account-iam-role | \
		awk '{print $$1 ":" $$2}' | xargs -r docker rmi
