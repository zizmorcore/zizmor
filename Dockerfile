# ------------------------------------------------------------------------------
# Prep image
#
# Observe that we do something wonky here: the "right" way to bootstrap
# zizmor is to directly install it from `apk`, since Wolfi OS provides a build.
#
# However, that doesn't work for us in practice, since Wolfi's downstream
# cadence can diverge significantly (24+ hours) from ours. We previously
# accepted that but now need faster turnarounds, so we use Wolfi OS to
# bootstrap uv and then `uv tool install` to bootstrap the right arch-specific
# binary. This also saves us a re-build of zizmor since we can re-use the PyPI
# builds.
# ------------------------------------------------------------------------------

FROM cgr.dev/chainguard/wolfi-base:latest AS prep

ARG ZIZMOR_VERSION

RUN set -eux && \
    apk update && \
    apk add uv

# installs to `/root/.local/bin/zizmor`
RUN uv tool install zizmor==${ZIZMOR_VERSION}

# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

FROM cgr.dev/chainguard/wolfi-base:latest

COPY --from=prep /root/.local/bin/zizmor /usr/bin/zizmor

# smoke test
RUN /usr/bin/zizmor --version

ENTRYPOINT ["/usr/bin/zizmor"]
