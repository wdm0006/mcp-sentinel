#!/usr/bin/env bash
# Resolve the single version tag a Release run builds.
#
# usage: select-release-tag.sh <event-name> <dispatch-input> <ref-name>
#
# A tag push carries the tag in the ref; a manual dispatch runs from a branch,
# so the tag has to be supplied as an input. Everything downstream (checkout,
# version validation, draft release) uses the one tag printed here.

set -euo pipefail

event_name="${1-}"
dispatch_tag="${2-}"
ref_name="${3-}"

case "$event_name" in
  workflow_dispatch)
    tag="$dispatch_tag"
    if [ -z "$tag" ]; then
      echo "::error::a manual release run requires the tag input, for example v0.1.0" >&2
      exit 1
    fi
    ;;
  push)
    tag="$ref_name"
    ;;
  *)
    echo "::error::unsupported event '$event_name': Release runs on a v* tag push or a manual dispatch" >&2
    exit 1
    ;;
esac

case "$tag" in
  v?*) ;;
  *)
    echo "::error::release tag '$tag' is not a version tag; expected something like v0.1.0" >&2
    exit 1
    ;;
esac

printf '%s\n' "$tag"
