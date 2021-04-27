SHELL := /bin/bash
export PYTHONPATH := $(PYTHONPATH):./lambda/src

include $(shell test -f .tardigrade-ci || curl -sSL -o .tardigrade-ci "https://raw.githubusercontent.com/plus3it/tardigrade-ci/master/bootstrap/Makefile.bootstrap"; echo .tardigrade-ci)

pytest/install:
	@ $(MAKE) install/pip/$(@D) PYPI_PKG_NAME=$(@D)
	@ python -m pip install \
		-r lambda/tests/requirements_dev.txt \
		-r tests/requirements_test.txt

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

.PHONY: terraform/pytest
terraform/pytest: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Starting test of Terraform lambda installation"
	@ echo "[$@] LocalStack must be running; 'make localstack/up' can "
	@ echo "[$@]    be used to start LocalStack"
	@ echo "[$@] Terraform 'apply' command is slow ... be patient !!!"
	pytest tests
	@ echo "[$@]: Completed successfully!"

.PHONY: localstack/pytest localstack/up localstack/down localstack/clean
localstack/pytest: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Running Terraform tests against LocalStack"
	DOCKER_RUN_FLAGS="--network host --rm" \
		TARDIGRADE_CI_DOCKERFILE=Dockerfile_test \
		$(MAKE) docker/run target=terraform/pytest
	@ echo "[$@]: Completed successfully!"

localstack/up: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Starting LocalStack container"
	docker-compose -f tests/docker-compose-localstack.yml up --detach

localstack/down: | guard/program/terraform guard/program/pytest
	@ echo "[$@] Stopping LocalStack container"
	docker-compose -f tests/docker-compose-localstack.yml down

localstack/clean: | localstack/down
	@ echo "[$@] Stopping and removing LocalStack container and images"
	set +o pipefail; docker images | grep lambci | \
		awk '{print $$1 ":" $$2}' | xargs -r docker rmi
	set +o pipefail; docker images | grep new-account-iam-role | \
		awk '{print $$1 ":" $$2}' | xargs -r docker rmi
