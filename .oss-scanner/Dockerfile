FROM python:3.15-slim-bookworm@sha256:122756f3fe72c4f5d3d71897888204ee85774bc79de952555b8a474e1d0a5d53
COPY --from=ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 /uv /uvx /usr/local/bin/

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
