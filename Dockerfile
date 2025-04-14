# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

FROM cgr.dev/chainguard/wolfi-base:latest

# Wolfi zizmor version to install
# https://edu.chainguard.dev/open-source/wolfi/apk-version-selection/
# (set as an argument to pair with zizmor releases)
ARG ZIZMOR_VERSION

RUN set -eux && \
    apk update && \
    apk add zizmor=~${ZIZMOR_VERSION} && \
    zizmor --version

# Set the entrypoint to zizmor
ENTRYPOINT ["/usr/bin/zizmor"]
