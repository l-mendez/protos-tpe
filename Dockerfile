FROM agodio/itba-so-multi-platform:3.0

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
