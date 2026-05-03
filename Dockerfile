FROM tabledevil/file-analysis:latest

USER root
ARG DEBIAN_FRONTEND=noninteractive

# System packages: Python 3.10 (deadsnakes) + libzbar (QR decoding) +
# poppler-utils (pdftoppm for PDF previews). REMnux ships node+npm via
# the base image; box-js is verified below and installed if missing.
RUN add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y --no-install-recommends \
        python3.10 \
        python3.10-venv \
        python3.10-dev \
        poppler-utils \
        libzbar0 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# box-js (dynamic JS sandbox) — used by ScriptAnalyzer when the analyst
# wants to detonate obfuscated droppers safely. REMnux base typically
# already ships it; we install if absent and fail the build if both
# attempts fail (no silent degradation in the container build).
RUN command -v box-js >/dev/null 2>&1 \
    || (command -v npm >/dev/null 2>&1 && npm install -g box-js) \
    || (echo "ERROR: box-js missing and npm unavailable" >&2 && false) \
    && box-js --help >/dev/null 2>&1

# Create venv with Python 3.10
RUN python3.10 -m venv /opt/matt/venv
ENV PATH="/opt/matt/venv/bin:${PATH}"

# Marker so tests know they're running inside the MATT container —
# unlocks @pytest.mark.docker tests that need box-js / libzbar / etc.
ENV MATT_IN_DOCKER=1

# Upgrade pip tooling
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy source and install with all extras (except lang — 1GB model download).
# qr extra requires libzbar (installed above); js+pdf extras pull in
# jsbeautifier / PyPDF2 / pdf2image.
COPY . /opt/matt/src/
RUN pip install --no-cache-dir \
    "/opt/matt/src[office,pdf,html,msg,7z,mime,tui,fuzzy,yara,js,qr,dev]"

# Sanity check at build time — fail the image build if --check reports
# unsatisfied core dependencies. Optional misses (eg. lang) are OK.
RUN matt --check 2>&1 | tee /tmp/matt-check.log \
    && ! grep -q "Missing core" /tmp/matt-check.log

# Switch back to remnux user
USER remnux
WORKDIR /data

CMD ["/bin/bash"]
