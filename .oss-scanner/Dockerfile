FROM python:3.13-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /uvx /usr/local/bin/

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
