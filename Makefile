SHELL := /bin/bash
export PYTHONPATH := $(PWD)/lambda/src

include $(shell test -f .tardigrade-ci || curl -sSL -o .tardigrade-ci "https://raw.githubusercontent.com/plus3it/tardigrade-ci/master/bootstrap/Makefile.bootstrap"; echo .tardigrade-ci)

pytest/install:
	@ $(MAKE) install/pip/$(@D) PYPI_PKG_NAME=$(@D)
	@ python -m pip install -r lambda/tests/requirements_dev.txt

python/deps:
	@ echo "[$@] Installing package dependencies"
	@ python -m pip install -r lambda/src/requirements.txt

python/test: | guard/program/pytest
python/test:
	@ echo "[$@] Starting Python tests"
	cd lambda && pytest
	@ echo "[$@]: Tests executed!"

.PHONY: python/deps python/test
