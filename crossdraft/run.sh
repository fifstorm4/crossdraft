#!/bin/sh
# Run CrossDraft in Docker against the current directory.
#
#   ./run.sh selftest
#   ./run.sh build present
#   ./run.sh analyse present --rounds 3 --export fig.svg
#
# Files land in the directory you ran this from, not inside the container.
# Pass IMAGE=... to pin a release:
#
#   IMAGE=ghcr.io/fifstorm/crossdraft:0.1.0 ./run.sh env present

set -eu
IMAGE="${IMAGE:-crossdraft}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE (once, a few minutes)" >&2
    docker build -t "$IMAGE" "$(dirname "$0")"
fi

exec docker run --rm -it -v "$PWD:/work" -u "$(id -u):$(id -g)" "$IMAGE" "$@"
