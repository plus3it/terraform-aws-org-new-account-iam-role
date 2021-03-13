SHELL := /bin/bash
export PYTHONPATH := $(PYTHONPATH):./lambda/src

include $(shell test -f .tardigrade-ci || curl -sSL -o .tardigrade-ci "https://raw.githubusercontent.com/plus3it/tardigrade-ci/master/bootstrap/Makefile.bootstrap"; echo .tardigrade-ci)

pytest/install:
	@ $(MAKE) install/pip/$(@D) PYPI_PKG_NAME=$(@D)
	@ python -m pip install \
		-r lambda/tests/requirements_dev.txt \
		-r tests/requirements_test.txt

python/deps:
	@ echo "[$@] Installing package dependencies"
	@ python -m pip install -r lambda/src/requirements.txt

python/test: | guard/program/pytest
python/test:
	@ echo "[$@] Starting Python tests"
	pytest lambda/tests
	@ echo "[$@]: Tests executed!"

terraform/pytest: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Starting test of Terraform lambda installation"
	@ echo "[$@] Terraform 'apply' command is slow ... be patient !!!"
	pytest tests
	@ echo "[$@]: Completed successfully!"

localstack/pytest: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Setting up network used by LocalStack, starting LocalStack"
	@ docker network create localstack
	@ docker-compose -f tests/docker-compose-localstack.yml up --detach
	@ echo "[$@] Running Terraform tests against LocalStack"
	@ DOCKER_RUN_FLAGS="--network host --rm" \
		$(MAKE) docker/run target=terraform/pytest
	@ echo "[$@] Stopping, removing LocalStack container and network"
	@ docker-compose -f tests/docker-compose-localstack.yml down --rmi all
	@ docker network rm localstack
	@ echo "[$@]: Completed successfully!"

.PHONY: python/deps python/test terraform/pytest
