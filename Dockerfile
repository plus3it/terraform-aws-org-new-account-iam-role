FROM plus3it/tardigrade-ci:0.15.0

COPY ./lambda/src/requirements.txt /src/requirements.txt
COPY ./lambda/tests/requirements_dev.txt /tests/requirements_dev.txt
COPY ./tests/requirements_test.txt /tests/requirements_test.txt

RUN python -m pip install --no-cache-dir \
    -r /src/requirements.txt \
    -r /tests/requirements_dev.txt \
    -r /tests/requirements_test.txt
