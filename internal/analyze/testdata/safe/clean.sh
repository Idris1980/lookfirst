#!/usr/bin/env bash
# Removes build output. ${BUILD_DIR:?} stops the script if the variable is empty.
set -euo pipefail

rm -rf "${BUILD_DIR:?}"/*
DB_PASSWORD="${DB_PASSWORD:-}"
echo "done"
