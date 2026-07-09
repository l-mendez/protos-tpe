FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        check \
        gdb \
        pkg-config \
        valgrind \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["bash"]
