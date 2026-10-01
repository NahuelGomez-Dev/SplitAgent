# SplitAgent toolbox - the agents' isolated execution environment.
#
# Everything the agents install or run happens here, never on the host.
# The workspace is bind-mounted at /workspace so tooling and data persist
# across runs while the container itself can be thrown away at any time.
#
# Editions:
#   standard (default) - Debian slim + a curated recon/exploitation toolset
#   kali               - Kali rolling, everything preinstalled (much larger)
#
# Build:  docker build -f docker/toolbox.Dockerfile --build-arg EDITION=standard -t splitagent-toolbox .
# The desktop app and the CLI build this for you; see splitagent/core/toolbox.py.

ARG EDITION=standard

# --------------------------------------------------------------------------- #
# Standard edition: Debian slim + curated tools
# --------------------------------------------------------------------------- #
FROM debian:bookworm-slim AS standard

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Core runtime + the tools that ship in Debian's main repos.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq unzip zip tar less nano vim-tiny \
        python3 python3-pip python3-venv pipx \
        nmap masscan netcat-openbsd dnsutils whois \
        dirb \
        libpcap0.8 net-tools iproute2 iputils-ping \
        openssl \
        && rm -rf /var/lib/apt/lists/*

# Go-based recon tools. Debian's packaged Go (1.19) is far too old for these
# projects, so we fetch an official toolchain, compile, then delete it.
ARG GO_VERSION=1.23.4
ENV GOBIN=/usr/local/bin \
    GOPATH=/opt/go \
    PATH=/usr/local/bin:/opt/go/bin:$PATH

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) goarch=amd64 ;; \
        arm64) goarch=arm64 ;; \
        *) goarch=amd64 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tgz; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm -f /tmp/go.tgz; \
    export PATH="/usr/local/go/bin:$PATH"; \
    go version; \
    GOFLAGS=-mod=mod go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
    GOFLAGS=-mod=mod go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
    GOFLAGS=-mod=mod go install github.com/projectdiscovery/httpx/cmd/httpx@latest; \
    GOFLAGS=-mod=mod go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest; \
    GOFLAGS=-mod=mod go install github.com/ffuf/ffuf/v2@latest; \
    GOFLAGS=-mod=mod go install github.com/OJ/gobuster/v3@latest; \
    rm -rf /usr/local/go /opt/go /root/go /root/.cache/go-build

# Python tooling in its own virtualenv so pip installs stay contained.
# nikto / sqlmap / whatweb come from pip because Debian main does not ship them.
RUN python3 -m venv /opt/venv \
        && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
        && /opt/venv/bin/pip install --no-cache-dir \
            requests httpx beautifulsoup4 dnspython shodan \
            sqlmap wafw00f
ENV PATH=/opt/venv/bin:$PATH \
    VIRTUAL_ENV=/opt/venv

# --------------------------------------------------------------------------- #
# Kali edition: everything, much larger
# --------------------------------------------------------------------------- #
FROM kalilinux/kali-rolling AS kali

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        kali-linux-headless nmap masscan nikto sqlmap whatweb wafw00f \
        gobuster ffuf dirb nuclei subfinder httpx-toolkit dnsx \
        python3 python3-pip python3-venv pipx git curl wget jq netcat-openbsd \
        && rm -rf /var/lib/apt/lists/*

ENV PATH=/usr/local/bin:$PATH

# --------------------------------------------------------------------------- #
# Shared runtime layer (applies to whichever edition was selected)
# --------------------------------------------------------------------------- #
FROM ${EDITION} AS runtime

# A non-root user owns the work; the entrypoint repairs the writable paths so
# bind-mounted volumes owned by root on the host still work, then drops to it.
ARG UID=1000
RUN (useradd -m -u ${UID} -s /bin/bash splitagent 2>/dev/null || true) \
        && mkdir -p /workspace \
        && chown -R ${UID}:${UID} /workspace /home/splitagent

# The entrypoint repairs writable paths (bind mounts arrive owned by root on
# the host) and stays alive. `docker exec` runs as root inside the container,
# which is what makes apt available; HOME defaults to /root for those shells.
RUN printf '#!/bin/sh\nset -e\n' > /usr/local/bin/splitagent-entrypoint \
    && printf 'mkdir -p /workspace/tools /workspace/recon /workspace/loot /workspace/notes /workspace/cache\n' >> /usr/local/bin/splitagent-entrypoint \
    && printf 'chown -R splitagent:splitagent /var/lib/apt/lists /workspace 2>/dev/null || true\n' >> /usr/local/bin/splitagent-entrypoint \
    && printf 'exec sleep infinity\n' >> /usr/local/bin/splitagent-entrypoint \
    && chmod +x /usr/local/bin/splitagent-entrypoint \
    && mkdir -p /var/lib/apt/lists/partial /var/cache/apt/archives/partial \
    && printf 'debconf debconf/frontend select Noninteractive\n' | debconf-set-selections \
    && printf 'Acquire::Retries "3";\nAPT::Install-Recommends "false";\n' > /etc/apt/apt.conf.d/99-splitagent

ENV SPLITAGENT_WORKSPACE=/workspace \
    SPLITAGENT_TOOLS=/workspace/tools \
    SPLITAGENT_RECON=/workspace/recon \
    SPLITAGENT_NOTES=/workspace/notes \
    HOME=/home/splitagent

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/splitagent-entrypoint"]
