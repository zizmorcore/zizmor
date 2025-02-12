FROM python:3.13-slim-bullseye AS build

LABEL org.opencontainers.image.source=https://github.com/woodruffw/zizmor

# Zizmor version to install (set as an argument to pair with zizmor releases)
ARG ZIZMOR_VERSION

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN set -eux && \
    apt-get update && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip install zizmor && \
    which zizmor

# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

FROM debian:bullseye-slim

# Copy necessary files from build stage
COPY --from=build /usr/local/bin/zizmor /app/zizmor

# Set the entrypoint to zizmor
ENTRYPOINT ["/app/zizmor"]
