# Dev/test container for building and exercising the linuxbpf boundary
# filter against a real Linux kernel and a real cgroup2 hierarchy -- the
# thing that can't be done on the macOS host this project was authored on.
#
# This is deliberately a single "everything in one image" build, not a
# slim multi-stage runtime image: the point is to have a shell inside a
# real Linux container where you can build, load, poke at with bpftool,
# and generate test traffic against the filter, all in one place.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/rustup/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        pkg-config \
        libelf-dev \
        zlib1g-dev \
        libssl-dev \
        bpftool \
        iproute2 \
        iptables \
        dnsutils \
        procps \
        less \
        vim-tiny \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# Stable toolchain builds the userspace `linuxbpf` binary; nightly +
# rust-src is what `aya-build` invokes itself (via `cargo +nightly`) to
# cross-compile `linuxbpf-ebpf` to the `bpfel-unknown-none` BPF target --
# see linuxbpf/build.rs.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustup toolchain install nightly --profile minimal --component rust-src \
    && rustup component add rustfmt clippy

# bpf-linker links the eBPF object; it depends on a specific LLVM version's
# libraries, which is exactly the "complexity of getting the setup right"
# its own docs warn about for building from source. cargo-binstall instead
# fetches its prebuilt release binary, sidestepping the LLVM version match
# entirely.
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
        https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh \
        | bash \
    && cargo binstall --no-confirm bpf-linker \
    && bpf-linker --version

WORKDIR /workspace
COPY . .

RUN cargo build --release

# Loading/attaching the eBPF programs needs real privileges at *run* time
# (see README.md "Docker"), not at build time, so this image just drops
# you into a shell with the built binary and bpftool ready:
#   docker run --rm -it --privileged linuxbpf
CMD ["bash"]
