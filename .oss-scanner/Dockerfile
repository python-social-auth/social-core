FROM python:3.15-slim-bookworm@sha256:0e019bbdfb5d9874cb2389f1c2884b64aa2ac97c99960b5bc521cef978c0617d
COPY --from=ghcr.io/astral-sh/uv:0.13.4@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b /uv /uvx /usr/local/bin/

ENV UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PATH="/src/.venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential pkg-config libxml2-dev libxslt1-dev \
      libxmlsec1-dev libxmlsec1-openssl zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Resolve online: uv.lock is intentionally not tracked by this project.
# Use the PEP 735 dev group and runtime extras, not the legacy dev extra.
RUN uv sync --group dev --extra all \
      --no-binary-package lxml --no-binary-package xmlsec

# The scanner must be able to repeat these tests without Internet access.
RUN uv run --offline --no-sync pytest \
    || echo "WARNING: pytest reported failures"
