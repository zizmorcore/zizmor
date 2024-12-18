FROM python:3.12-slim-bookworm AS build

LABEL org.opencontainers.image.source=https://github.com/woodruffw/zizmor

# Zizmor version to install (set as an argument to pair with zizmor releases)
ARG ZIZMOR_VERSION

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Add Rust to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

RUN set -eux && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Rust using rustup
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    rustup update 

RUN pip install zizmor=="${ZIZMOR_VERSION}" && \
    which zizmor

# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

FROM python:3.12-slim-bookworm

# Copy necessary files from build stage
COPY --from=build /usr/local/bin/zizmor /usr/local/bin/zizmor

# Set the entrypoint to zizmor
ENTRYPOINT ["/usr/local/bin/zizmor"]