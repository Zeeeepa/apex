FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    iptables \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list

# Install Docker + Compose plugin
RUN apt-get update && apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

# Create docker group and add root user
RUN groupadd -f docker && usermod -aG docker root

# Setup entrypoint to start Docker daemon
RUN echo '#!/bin/sh' > /docker-entrypoint.sh \
    && echo 'set -e' >> /docker-entrypoint.sh \
    && echo '' >> /docker-entrypoint.sh \
    && echo '# Start Docker daemon in the background' >> /docker-entrypoint.sh \
    && echo 'dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2375 &' >> /docker-entrypoint.sh \
    && echo '' >> /docker-entrypoint.sh \
    && echo '# Wait for Docker to be ready' >> /docker-entrypoint.sh \
    && echo 'timeout=30' >> /docker-entrypoint.sh \
    && echo 'while ! docker info >/dev/null 2>&1; do' >> /docker-entrypoint.sh \
    && echo '  timeout=$((timeout - 1))' >> /docker-entrypoint.sh \
    && echo '  if [ $timeout -le 0 ]; then' >> /docker-entrypoint.sh \
    && echo '    echo "Docker daemon failed to start"' >> /docker-entrypoint.sh \
    && echo '    exit 1' >> /docker-entrypoint.sh \
    && echo '  fi' >> /docker-entrypoint.sh \
    && echo '  sleep 1' >> /docker-entrypoint.sh \
    && echo 'done' >> /docker-entrypoint.sh \
    && echo '' >> /docker-entrypoint.sh \
    && echo 'echo "Docker daemon is ready"' >> /docker-entrypoint.sh \
    && echo '' >> /docker-entrypoint.sh \
    && echo '# Keep container running' >> /docker-entrypoint.sh \
    && echo 'exec "$@"' >> /docker-entrypoint.sh \
    && chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]