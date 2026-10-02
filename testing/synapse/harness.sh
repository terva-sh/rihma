#!/usr/bin/env bash
# Throwaway local Synapse plus Element Web for the live suite (`just e2e`).
#
# Adapted from terva-conn-matrix's testing/synapse. Deliberately NOT a real
# Matrix server: server_name `localhost`, no federation, open registration,
# sqlite, published on 127.0.0.1 only, all state under ./data (gitignored).
# The signing key is generated into ./data on first start, so nothing
# secret-shaped lives in the repository.
#
# Plain `run` commands rather than compose, so it needs only podman (or
# docker, via CONTAINER_ENGINE). Ports and container names differ from
# terva-conn-matrix's harness so the two can run side by side.
#
# usage: harness.sh up | down | clean | status
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
data=${SYNAPSE_DATA_DIR:-"$here/data"}

engine=${CONTAINER_ENGINE:-}
if [ -z "$engine" ]; then
	if command -v podman >/dev/null; then engine=podman; else engine=docker; fi
fi

synapse_port=${SYNAPSE_PORT:-18108}
element_port=${ELEMENT_PORT:-18109}
synapse_image=${SYNAPSE_IMAGE:-ghcr.io/element-hq/synapse:latest}
element_image=${ELEMENT_IMAGE:-docker.io/vectorim/element-web:latest}
synapse_name=${SYNAPSE_NAME:-rihma-synapse}
element_name=${ELEMENT_NAME:-rihma-element}

render() { # template -> data/ with the port filled in
	sed "s/@SYNAPSE_PORT@/$synapse_port/g" "$here/$1.in" >"$data/$1"
}

exists() { "$engine" container exists "$1" 2>/dev/null || "$engine" inspect "$1" >/dev/null 2>&1; }

up() {
	mkdir -p "$data"
	render homeserver.yaml
	render element-config.json

	if ! exists "$synapse_name"; then
		# Synapse runs as the container's root: under rootless podman that is
		# the invoking user, so ./data stays removable without sudo. Under
		# rootful docker it is real root and `clean` will need sudo, as in
		# terva-conn-matrix; that path has not been run here.
		"$engine" run -d --name "$synapse_name" \
			-p "127.0.0.1:$synapse_port:8008" \
			-v "$data/homeserver.yaml:/config/homeserver.yaml:ro" \
			-v "$here/log.config:/config/log.config:ro" \
			-v "$data:/data" \
			--entrypoint /bin/sh "$synapse_image" -c \
			'python -m synapse.app.homeserver --config-path /config/homeserver.yaml --generate-keys &&
			 exec python -m synapse.app.homeserver --config-path /config/homeserver.yaml' >/dev/null
	else
		"$engine" start "$synapse_name" >/dev/null
	fi

	if ! exists "$element_name"; then
		# The image runs nginx as a non-root user on ELEMENT_WEB_PORT, default
		# 80. Docker lets containers bind low ports; podman does not, so use
		# 8080, which works on both.
		"$engine" run -d --name "$element_name" \
			-e ELEMENT_WEB_PORT=8080 \
			-p "127.0.0.1:$element_port:8080" \
			-v "$data/element-config.json:/app/config.json:ro" \
			"$element_image" >/dev/null
	else
		"$engine" start "$element_name" >/dev/null
	fi

	wait_for "$synapse_name" "http://127.0.0.1:$synapse_port/health"
	wait_for "$element_name" "http://127.0.0.1:$element_port/config.json"
	echo "synapse up:  http://127.0.0.1:$synapse_port (server_name: localhost, throwaway)"
	echo "element up:  http://127.0.0.1:$element_port (already pointed at the throwaway)"
}

wait_for() { # container url
	for _ in $(seq 1 120); do
		if curl -fsS "$2" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	echo "$1 did not answer $2 in 120s; last log lines:" >&2
	"$engine" logs --tail 30 "$1" >&2 || true
	return 1
}

down() {
	for c in "$element_name" "$synapse_name"; do
		if exists "$c"; then "$engine" rm -f "$c" >/dev/null; fi
	done
}

clean() {
	down
	rm -rf "$data"
}

status() {
	"$engine" ps -a --filter "name=^($synapse_name|$element_name)$" --format '{{.Names}}  {{.Status}}'
	if curl -fsS "http://127.0.0.1:$synapse_port/health" >/dev/null 2>&1; then
		echo "synapse healthy on 127.0.0.1:$synapse_port"
	else
		echo "synapse not answering on 127.0.0.1:$synapse_port"
	fi
}

case "${1:-}" in
up) up ;;
down) down ;;
clean) clean ;;
status) status ;;
*)
	echo "usage: $0 up | down | clean | status" >&2
	exit 2
	;;
esac
