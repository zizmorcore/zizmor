#!/usr/bin/env bash

# wolfi-update-check.sh:
# Get the latest Docker image for zizmor and compare its version to the
# latest version of zizmor available via Wolfi OS.
#
# If the two don't match, create or update a tracking issue in
# the zizmor repository.

set -euo pipefail

info() {
    echo "::notice::${*}"
}

warn() {
    echo "::warning::${*}"
}

err() {
    echo "::error::${*}"
}

die() {
  err "${*}"
  exit 1
}

get_docker_version() {
    gh api \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      /orgs/zizmorcore/packages/container/zizmor/versions \
    | jq -r '
        .[].metadata.container.tags
        | select(.[] | contains("latest"))
        | del(.[] | select(. == "latest"))[0]'
}

get_wolfi_version() {
    curl -sL https://packages.wolfi.dev/os/aarch64/APKINDEX.tar.gz \
    | tar -Oxz APKINDEX \
    | awk -F':' '$1 == "P" {printf "%s ", $2} $1 == "V" {printf "%s\n", $2}' \
    | grep "zizmor" \
    | tail -n 1 \
    | cut -d ' ' -f 2 \
    | cut -d '-' -f 1
}

docker_version=$(get_docker_version)
wolfi_version=$(get_wolfi_version)

[[ -z "${docker_version}" ]] && die "Failed to retrieve latest Docker version for zizmor"
[[ -z "${wolfi_version}" ]] && die "Failed to retrieve latest Wolfi version for zizmor"

if [[ "${docker_version}" == "${wolfi_version}" ]]; then
    info "Docker and Wolfi versions do not diverge (${docker_version})"
    exit 0
fi

title="[BOT] New Wolfi OS version for zizmor: ${wolfi_version}"
assignee="woodruffw"
label="wolfi-zizmor-bump"
body="
:robot: :warning: :robot:

Wolfi OS has published a new version of zizmor: \`${wolfi_version}\`.

The latest Docker image for zizmor is \`${docker_version}\`, which may be
behind the new Wolfi version.

Please review the versions manually and, if a Docker update is needed,
dispatch it appropriately. Maintainers can do this locally with:

    gh workflow run release-docker.yml --field version=${docker_version}
"

issue_exists=$(
    gh issue list \
    --label "${label}" \
    --json number \
    --jq '.[0].number' \
)

if [[ -n "${issue_exists}" ]]; then
    info "Adding comment to #${issue_exists}"
    gh issue comment "${issue_exists}" \
        --body "${body}"
else
    info "Creating new issue"
    gh issue create \
        --title "${title}" \
        --body "${body}" \
        --label "${label}" \
        --assignee "${assignee}"
fi
