FROM python:3.11-alpine

ENV \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false

RUN python -m pip install --upgrade poetry~=1.7.1

WORKDIR /opt/app

COPY pyproject.toml poetry.lock ./
RUN poetry install --only=main --no-root

COPY . .

CMD ["waitress-serve", "--host=0.0.0.0", "--port=8080", "server:application"]
