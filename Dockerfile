FROM plus3it/tardigrade-ci:0.24.13

COPY ./lambda/src/requirements.txt /app/requirements.txt
COPY ./requirements/requirements_dev.txt /app/requirements_dev.txt
COPY ./requirements/requirements_test.txt /app/requirements_test.txt
COPY ./requirements/requirements_common.txt /app/requirements_common.txt

RUN python -m pip install --no-cache-dir \
    -r /app/requirements.txt \
    -r /app/requirements_dev.txt \
    -r /app/requirements_test.txt
