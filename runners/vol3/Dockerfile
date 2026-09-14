FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        curl \
        libssl-dev \
        libffi-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/runner

COPY requirements.txt /opt/runner/requirements.txt
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r /opt/runner/requirements.txt

# Optional accelerators / extra plugin support. Never fail the build on these.
RUN pip install yara-python capstone pycryptodome || true

COPY runner.py /opt/runner/runner.py

RUN mkdir -p /evidence /symbols /artifacts

EXPOSE 9003
CMD ["python", "/opt/runner/runner.py"]
