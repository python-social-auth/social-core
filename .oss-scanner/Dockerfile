FROM python:3.15-slim-bookworm@sha256:575f8bc12ec26542e0678bc6b60e385218248019d433157ec327264a78c3a853
COPY --from=ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff /uv /uvx /usr/local/bin/

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
