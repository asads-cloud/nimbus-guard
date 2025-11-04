# syntax=docker/dockerfile:1.7

# Nimbus Guard Scanner — Production Dockerfile
# - Small, reproducible image
# - Caching for faster rebuilds
# - Non-root user for safer runtime
# - Clear layering and comments for auditors & future-you

# If your org uses a golden/base image, swap FROM to that image and keep the rest.

ARG PYTHON_VERSION=3.12-slim-bookworm
FROM python:${PYTHON_VERSION} AS runtime

# ---- Base env & pip hygiene (deterministic + quiet) ---------------------------------------------

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Minimal OS deps; add only what the scanner truly needs.
# Keep apt metadata small and layer tidy.
RUN apt-get update -y \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# ---- App directory & unprivileged user ----------------------------------------------------------------
WORKDIR /app

# Create a non-root user (uid/gid 10001 is a common choice in containers)
RUN groupadd -g 10001 appuser \
 && useradd -r -u 10001 -g appuser appuser \
 && mkdir -p /app/out \
 && chown -R appuser:appuser /app

# ---- Python deps (cached layer) --------------------------------------------------------------------
# Only copy the requirements file first so dependency installs are cached
COPY scanner/requirements.txt /app/requirements.txt

# pin & verify with hashes using pip-compile output.
# If you use hashes, add: --require-hashes
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

# ---- Application code -------------------------------------------------------------------------------
# Copy only what is needed at runtime (respect .dockerignore to keep image lean)
COPY scanner/ /app/

# ---- Runtime metadata & defaults ---------------------------------------------------------------------
# declare a default output directory; can be overridden at run time
ENV NG_OUT=/app/out

# Informational labels (helpful in registries and for auditing SBOMs)
LABEL org.opencontainers.image.title="Nimbus Guard Scanner" \
      org.opencontainers.image.description="AWS configuration scanner producing JSON/Markdown/HTML reports." \
      org.opencontainers.image.source="https://example.invalid/repo" \
      org.opencontainers.image.licenses="Apache-2.0"

# Drop privileges for runtime
USER appuser

# Default entrypoint mirrors local/CI parity
ENTRYPOINT ["python", "-m", "nimbus_guard.runner"]
