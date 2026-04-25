FROM ubuntu:24.04

LABEL maintainer="BinSmasher Team" \
      description="BinSmasher — Binary Exploitation Framework" \
      version="4.2.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    gdb gdbserver \
    radare2 \
    socat netcat-openbsd \
    gcc gcc-multilib g++ \
    binutils file patchelf \
    git curl wget \
    ruby ruby-dev \
    build-essential \
    libssl-dev libffi-dev \
    # AFL++
    afl++ \
    # checksec
    checksec \
    # For one_gadget (Ruby gem)
    && gem install one_gadget --no-document 2>/dev/null || true \
    # For ROPgadget (already in pwntools but keep separate)
    && pip3 install --break-system-packages ROPgadget ropper \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── pwndbg ─────────────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && cd /opt/pwndbg && ./setup.sh --quiet 2>/dev/null || true

# ── Python dependencies ────────────────────────────────────────────────────────
RUN pip3 install --break-system-packages \
    pwntools \
    rich \
    boofuzz \
    frida-tools \
    capstone \
    keystone-engine \
    # angr (optional — large but powerful)
    angr \
    && pip3 install --break-system-packages --upgrade pip

# ── BinSmasher ────────────────────────────────────────────────────────────────
WORKDIR /binsmasher
COPY . /binsmasher/
RUN pip3 install --break-system-packages -e .

# ── Setup core dump handling ───────────────────────────────────────────────────
RUN echo "kernel.core_pattern=/tmp/cores/core.%e.%p" >> /etc/sysctl.conf || true \
    && mkdir -p /tmp/cores

# ── GDB init ──────────────────────────────────────────────────────────────────
RUN echo "source /opt/pwndbg/gdbinit.py" > /root/.gdbinit 2>/dev/null || true

# ── Entry point ───────────────────────────────────────────────────────────────
ENTRYPOINT ["binsmasher"]
CMD ["--help"]
