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
	@ echo "[$@] Terraform 'apply' command is slow ... be patient"
	pytest tests
	@ echo "[$@]: Completed successfully!"

.PHONY: python/deps python/test terraform/pytest
