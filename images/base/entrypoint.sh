#!/usr/bin/env sh
set -eu

export PATH="/root/.local/bin:/root/.opencode/bin:$PATH"
export ADA_GATEWAY="${ADA_GATEWAY:-http://ada-gateway.ada-system.svc:8080}"
gateway="${ADA_GATEWAY%/}"
workspace="${WORKSPACE:-/workspace}"
access="${ACCESS:-tty}"
harness="${HARNESS:-}"
ts_authkey="${TS_AUTHKEY:-}"
unset TS_AUTHKEY

install_harness() {
	case "$1" in
		""|none)
			;;
		opencode)
			command -v opencode >/dev/null 2>&1 || curl -fsSL https://opencode.ai/install | bash
			;;
		claude)
			command -v claude >/dev/null 2>&1 || curl -fsSL https://claude.ai/install.sh | bash
			;;
		agy)
			command -v agy >/dev/null 2>&1 || curl -fsSL https://antigravity.google/cli/install.sh | bash
			;;
		*)
			echo "entrypoint: unknown HARNESS '$1' (expected opencode, claude, agy, or none)" >&2
			exit 1
			;;
	esac
}

install_rex() {
	command -v rex >/dev/null 2>&1 || curl -fsSL "${REX_INSTALL_URL:-https://pkgs.superlogical.com/rex/install.sh}" | sh
}

install_tailscale() {
	command -v tailscaled >/dev/null 2>&1 || curl -fsSL https://tailscale.com/install.sh | sh
}

install_harness "$harness"

if [ "$access" = "rex" ] || [ "${WITH_REX:-false}" = "true" ]; then
	install_rex
fi

if [ "${WITH_TAILSCALE:-false}" = "true" ] || { [ -n "$ts_authkey" ] && [ "$access" != "rex" ]; }; then
	install_tailscale
fi

if [ "${1:-}" = "--install-only" ]; then
	exit 0
fi

if [ "$gateway" != "http://ada-gateway.ada-system.svc:8080" ]; then
	git config --system --remove-section "url.http://ada-gateway.ada-system.svc:8080/github/" 2>/dev/null || true
	git config --system url."$gateway/github/".insteadOf "https://github.com/"
fi

if [ -n "$ts_authkey" ] && command -v tailscaled >/dev/null 2>&1; then
	mkdir -p /tmp/tailscale
	tailscaled \
		--tun=userspace-networking \
		--state=/tmp/tailscale/tailscaled.state \
		--socket=/tmp/tailscale/tailscaled.sock &
	tailscale --socket=/tmp/tailscale/tailscaled.sock up \
		--authkey="$ts_authkey" \
		--hostname="${ADA_SANDBOX_NAME:-$(hostname)}" \
		--advertise-tags="${TS_TAGS:-tag:ada}"
fi

mkdir -p "$workspace"
if [ -n "${ADA_REPO:-}" ] && [ ! -d "$workspace/.git" ]; then
	git clone "https://github.com/${ADA_REPO%.git}.git" "$workspace"
fi
cd "$workspace"

if [ $# -gt 0 ]; then
	touch /tmp/ada-ready
	exec "$@"
fi

case "$access" in
	rex)
		if [ -S /tmp/tailscale/tailscaled.sock ]; then
			touch /tmp/ada-ready
			exec rex server run --tailscaled-socket=/tmp/tailscale/tailscaled.sock --extra-listen=tailnet
		fi
		if [ -n "$ts_authkey" ]; then
			mkdir -p /tmp/tailscale
			printf '%s' "$ts_authkey" >/tmp/tailscale/authkey
			chmod 600 /tmp/tailscale/authkey
			touch /tmp/ada-ready
			exec rex server run \
				--tailscale \
				--tailscale-hostname="${ADA_SANDBOX_NAME:-$(hostname)}" \
				--tailscale-auth-key-file=/tmp/tailscale/authkey \
				--tailscale-advertise-tag="${TS_TAGS:-tag:ada}"
		fi
		touch /tmp/ada-ready
		exec rex server run
		;;
	tty|headless)
		touch /tmp/ada-ready
		exec sleep infinity
		;;
	*)
		echo "entrypoint: unknown ACCESS mode '$access' (expected rex, tty, or headless)" >&2
		exit 1
		;;
esac
