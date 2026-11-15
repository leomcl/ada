FROM tailscale/tailscale:stable AS tailscale

FROM node:22-bookworm-slim

ARG AGY_INSTALL_URL="https://antigravity.google/cli/install.sh"
ARG REX_INSTALL_URL="https://pkgs.superlogical.com/rex/install.sh"

RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	curl \
	git \
	jq \
	less \
	openssh-client \
	procps \
	ripgrep \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscaled /usr/local/bin/

RUN npm install -g opencode-ai @anthropic-ai/claude-code \
	&& npm cache clean --force

RUN if [ -n "$AGY_INSTALL_URL" ]; then \
		curl -fsSL "$AGY_INSTALL_URL" | bash && \
		if [ -x /root/.local/bin/agy ]; then mv /root/.local/bin/agy /usr/local/bin/agy; fi; \
	fi

RUN if [ -n "$REX_INSTALL_URL" ]; then \
		curl -fsSL "$REX_INSTALL_URL" | sh; \
	fi

ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
	DISABLE_AUTOUPDATER=1 \
	ADA_GATEWAY=http://ada-gateway.ada-system.svc:8080 \
	OPENAI_BASE_URL=http://ada-gateway.ada-system.svc:8080/v1 \
	ANTHROPIC_BASE_URL=http://ada-gateway.ada-system.svc:8080/anthropic \
	GEMINI_API_BASE_URL=http://ada-gateway.ada-system.svc:8080/google \
	GOOGLE_GEMINI_BASE_URL=http://ada-gateway.ada-system.svc:8080/google

COPY gitconfig /etc/gitconfig
COPY ada-pr /usr/local/bin/ada-pr
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/local/bin/ada-pr /entrypoint.sh \
	&& mkdir -p /workspace

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
