FROM tabledevil/file-analysis:latest

USER root
ARG DEBIAN_FRONTEND=noninteractive

# Python 3.10 from deadsnakes (base image has 3.8, MATT needs 3.10+)
RUN add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y --no-install-recommends \
        python3.10 \
        python3.10-venv \
        python3.10-dev \
        poppler-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create venv with Python 3.10
RUN python3.10 -m venv /opt/matt/venv
ENV PATH="/opt/matt/venv/bin:${PATH}"

# Upgrade pip tooling
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy source and install with all extras (except lang — 1GB model download)
COPY . /opt/matt/src/
RUN pip install --no-cache-dir "/opt/matt/src[office,pdf,html,msg,7z,mime,tui,fuzzy,yara,js,dev]"

# Switch back to remnux user
USER remnux
WORKDIR /data

CMD ["/bin/bash"]
