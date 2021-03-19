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

.PHONY: terraform/terratest
terraform/terratest: TIMEOUT ?= 20m
terraform/terratest:| guard/program/terraform guard/program/go
	@ echo "[$@] Starting Terratest against lambda installation"
	@ echo "[$@] Terraform 'apply' command is slow ... be patient !!!"
	cd $(TERRAFORM_TEST_DIR) && go test -count=1 -timeout $(TIMEOUT)
	@ echo "[$@]: Completed successfully!"

.PHONY: terratest/setup
terratest/setup:
	@ echo "[$@] Create go.mod, go.sum files with updated dependencies"
	go version
	cd $(TERRAFORM_TEST_DIR) && rm -f go.mod go.sum
	cd $(TERRAFORM_TEST_DIR) && go mod init tardigrade-ci/tests
	cd $(TERRAFORM_TEST_DIR) && go mod tidy
	cd $(TERRAFORM_TEST_DIR) && go mod edit -replace github.com/gruntwork-io/terratest=github.com/ffernandezcast/terratest@v0.28.6-0.20201201084725-13e8a4c156b8
	cd $(TERRAFORM_TEST_DIR) && go mod tidy
	@ echo "[$@]: Completed successfully!"

.PHONY: terratest/docker
terratest/internal_to_docker:
	@ echo "[$@] Setup and run the Terratests within docker."
	$(MAKE) terratest/setup
	$(MAKE) terraform/terratest
	@ echo "[$@]: Completed successfully!"

.PHONY: localstack/terratest localstack/up localstack/down localstack/clean
localstack/terratest: | guard/program/terraform guard/program/go
	@ echo "[$@] Running Terraform tests against LocalStack"
	DOCKER_RUN_FLAGS="--network host --rm -e AWS_ACCESS_KEY_ID='mock_access_key' -e AWS_SECRET_ACCESS_KEY='mock_secret_key'" \
		TARDIGRADE_CI_DOCKERFILE=Dockerfile_terratest \
		$(MAKE) docker/run target=terratest/internal_to_docker
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
