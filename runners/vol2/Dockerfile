# Volatility 2.6.1 needs Python 2.7, which no modern base image ships by
# default.  Ubuntu 20.04 is the last LTS that still packages python2.7, so we
# quarantine the whole legacy stack in this one container.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        python2 \
        python2-dev \
        build-essential \
        wget \
        ca-certificates \
        git \
        unzip \
        libssl-dev \
        libffi-dev \
        zlib1g-dev \
        automake \
        libtool \
        make \
        pkg-config \
        flex \
        bison \
    && rm -rf /var/lib/apt/lists/*

# pip for Python 2.7 (bootstrap.pypa.io keeps a frozen 2.7 installer)
RUN wget -q https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py \
    && python2 /tmp/get-pip.py "pip<21" "setuptools<45" "wheel<0.34" \
    && rm -f /tmp/get-pip.py

# Core Volatility 2 dependencies.  Versions pinned to the last py2 releases.
RUN python2 -m pip install --no-cache-dir \
        pycryptodome==3.9.9 \
        distorm3==3.4.4 \
        pytz==2021.1 \
        openpyxl==2.6.4 \
        pillow==6.2.2 \
    || python2 -m pip install --no-cache-dir pycryptodome distorm3 pytz

# Optional: YARA support (yarascan plugin).  Never fail the image over it.
RUN python2 -m pip install --no-cache-dir yara-python==3.11.0 || \
    echo "WARNING: yara-python unavailable - the yarascan plugin will be disabled"

# Optional: faster JSON rendering
RUN python2 -m pip install --no-cache-dir ujson || true

# Volatility 2.6.1
RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility.git /opt/volatility

ENV VOL2_HOME=/opt/volatility \
    RUNNER_PORT=9002

WORKDIR /opt/runner
COPY runner.py /opt/runner/runner.py

RUN mkdir -p /evidence /profiles /artifacts

EXPOSE 9002
CMD ["python2", "/opt/runner/runner.py"]
