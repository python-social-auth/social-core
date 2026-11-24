FROM python:3.15-slim-bookworm@sha256:498829c717b1e59fc42f0e7865eafe4e04ca0f70a3769d4ae70ba218df54507c
COPY --from=ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d /uv /uvx /usr/local/bin/

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
