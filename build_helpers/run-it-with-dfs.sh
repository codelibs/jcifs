#!/usr/bin/env bash
#
# Runs the SMB integration tests against Samba listening on port 445 inside a
# Docker network, with the test JVM on the same network.
#
# Plain "mvn verify" publishes Samba on a mapped port, and a DFS referral names a
# host but no port, so the DFS tests skip there. This script gives the server the
# default port inside the network instead, which lets them run even when the
# host's own 445 is taken - a Mac with file sharing on, for instance.
#
# Any extra arguments are passed to Maven, e.g.
#   ./build_helpers/run-it-with-dfs.sh -Dit.test=DfsIT
set -euo pipefail

NETWORK=jcifs-it-net
CONTAINER=jcifs-it-samba-net
IMAGE=jcifs-it-samba:local
MAVEN_IMAGE=${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-17}
PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -t "$IMAGE" "$PROJECT_ROOT/build_helpers/samba"
docker network create "$NETWORK" >/dev/null 2>&1 || true

# The DFS links have to name the host the client will reach, which inside the
# network is the container's alias.
docker run -d --name "$CONTAINER" --network "$NETWORK" --network-alias samba \
    -e SMB_DFS_TARGET_HOST=samba "$IMAGE" >/dev/null

# The preflight polls until the server answers, so there is nothing to wait for
# here. Running as the invoking user keeps target/ owned by them.
docker run --rm --network "$NETWORK" \
    -v "$PROJECT_ROOT":/work -w /work \
    -v "$HOME/.m2":/var/maven/.m2 \
    -u "$(id -u):$(id -g)" \
    -e MAVEN_CONFIG=/var/maven/.m2 \
    -e JCIFS_IT_BACKEND=samba \
    -e JCIFS_IT_HOST=samba \
    -e JCIFS_IT_PORT=445 \
    -e JCIFS_IT_USER=testuser1 \
    -e JCIFS_IT_REQUIRED=true \
    "$MAVEN_IMAGE" \
    mvn -B -Duser.home=/var/maven verify "$@"
