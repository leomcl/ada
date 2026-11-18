FROM debian:bookworm-slim

ARG HARNESS=""
ARG WITH_REX="false"
ARG WITH_TAILSCALE="false"

RUN apt-get update && apt-get install -y --no-install-recommends \
	bash \
	ca-certificates \
	curl \
	git \
	jq \
	less \
	openssh-client \
	procps \
	ripgrep \
	tar \
	unzip \
	&& rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:/root/.opencode/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
	CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
	DISABLE_AUTOUPDATER=1

COPY gitconfig /etc/gitconfig
COPY ada-pr /usr/local/bin/ada-pr
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/local/bin/ada-pr /entrypoint.sh \
	&& mkdir -p /workspace \
	&& HARNESS="$HARNESS" WITH_REX="$WITH_REX" WITH_TAILSCALE="$WITH_TAILSCALE" /entrypoint.sh --install-only

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
