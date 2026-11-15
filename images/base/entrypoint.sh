#!/usr/bin/env sh
set -eu

export ADA_GATEWAY="${ADA_GATEWAY:-http://ada-gateway.ada-system.svc:8080}"
gateway="${ADA_GATEWAY%/}"
workspace="${WORKSPACE:-/workspace}"
access="${ACCESS:-tty}"

if [ -n "${ADA_TOKEN:-}" ]; then
	export OPENAI_BASE_URL="${OPENAI_BASE_URL:-$gateway/v1}"
	export OPENAI_API_KEY="${OPENAI_API_KEY:-$ADA_TOKEN}"
	export ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-$gateway/anthropic}"
	export ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_AUTH_TOKEN:-$ADA_TOKEN}"
	export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-$ADA_TOKEN}"
	export GEMINI_API_BASE_URL="${GEMINI_API_BASE_URL:-$gateway/google}"
	export GOOGLE_GEMINI_BASE_URL="${GOOGLE_GEMINI_BASE_URL:-$gateway/google}"
	export GEMINI_API_KEY="${GEMINI_API_KEY:-$ADA_TOKEN}"
fi

if [ "$gateway" != "http://ada-gateway.ada-system.svc:8080" ]; then
	git config --global url."$gateway/github/".insteadOf "https://github.com/"
fi

if [ -n "${TS_AUTHKEY:-}" ]; then
	mkdir -p /tmp/tailscale
	tailscaled \
		--tun=userspace-networking \
		--state=/tmp/tailscale/tailscaled.state \
		--socket=/tmp/tailscale/tailscaled.sock &
	tailscale --socket=/tmp/tailscale/tailscaled.sock up \
		--authkey="$TS_AUTHKEY" \
		--hostname="${ADA_SANDBOX_NAME:-$(hostname)}" \
		--advertise-tags="${TS_TAGS:-tag:ada}"
fi

mkdir -p "$workspace"
if [ -n "${ADA_REPO:-}" ] && [ ! -d "$workspace/.git" ]; then
	git clone "https://github.com/${ADA_REPO%.git}.git" "$workspace"
fi
cd "$workspace"

if [ $# -gt 0 ]; then
	exec "$@"
fi

case "$access" in
	rex)
		if [ -S /tmp/tailscale/tailscaled.sock ]; then
			exec rex server run --tailscaled-socket=/tmp/tailscale/tailscaled.sock --extra-listen=tailnet
		fi
		exec rex server run
		;;
	tty|headless)
		exec sleep infinity
		;;
	*)
		echo "entrypoint: unknown ACCESS mode '$access' (expected rex, tty, or headless)" >&2
		exit 1
		;;
esac
