#!/usr/bin/env bash

# Turns a target-specific release build into an appropriately
# named archive for distribution via a GitHub release.
#
# Expects to be run from the root of the repository.

set -eo pipefail

if [[ -z "${TARGET}" ]]; then
  >&2 echo "Error: TARGET environment variable not set"
  exit 1
fi

TARGET_DIR="./target"
RELEASE_DIR="${TARGET_DIR}/${TARGET}/release"

if [[ ! -d "${RELEASE_DIR}" ]]; then
  >&2 echo "Error: missing target release directory?"
  exit 1
fi

ARCHIVE_DIR="${TARGET_DIR}/archive/zizmor-${TARGET}"
mkdir -p "${ARCHIVE_DIR}"
cp "${RELEASE_DIR}/zizmor" "${ARCHIVE_DIR}/zizmor"

if [[ "${TARGET}" == *"windows"* ]]; then
  ARCHIVE_FILE="${TARGET_DIR}/archive/zizmor-${TARGET}.zip"
  7z a "${ARCHIVE_FILE}" "${ARCHIVE_DIR}"/*
else
  ARCHIVE_FILE="${TARGET_DIR}/archive/zizmor-${TARGET}.tar.gz"
  tar -C "${ARCHIVE_DIR}" -czf "${ARCHIVE_FILE}" .
fi

if [[ -z "${GITHUB_OUTPUT}" ]]; then
  echo "${ARCHIVE_FILE}"
else
  echo "filename=${ARCHIVE_FILE}" >> "${GITHUB_OUTPUT}"
fi
