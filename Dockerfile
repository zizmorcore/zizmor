# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

FROM cgr.dev/chainguard/wolfi-base:latest

RUN set -eux && \
    apk update && \
    apk add zizmor && \
    which zizmor

# Set the entrypoint to zizmor
ENTRYPOINT ["/usr/bin/zizmor"]
