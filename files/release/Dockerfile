FROM python:3.8.2-slim-buster

RUN apt-get update && \
    apt-get install -y --no-install-recommends make gettext git curl

COPY ./files/release/pypirc.template /
COPY ./files/release/entrypoint.sh /
ADD . /code

WORKDIR /code

ENTRYPOINT ["/entrypoint.sh"]
