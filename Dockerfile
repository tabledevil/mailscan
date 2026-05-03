FROM tabledevil/file-analysis:latest

USER root
ARG DEBIAN_FRONTEND=noninteractive

# Base image is Ubuntu 24.04 (Python 3.12 stock) — no third-party PPA
# needed. We just add the system libraries MATT's optional analyzers
# require: libzbar (QR/barcode decoding for QRAnalyzer) and poppler
# (pdftoppm for PDF preview generation).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-venv \
        python3-dev \
        build-essential \
        poppler-utils \
        libzbar0 \
        zbar-tools \
        libfuzzy-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# box-js (dynamic JS sandbox) — used by ScriptAnalyzer to detonate
# obfuscated droppers safely. REMnux base ships it pre-installed; we
# fall back to `npm install -g box-js` if absent. Build fails loudly
# if neither path produces a working binary.
RUN command -v box-js >/dev/null 2>&1 \
    || (command -v npm >/dev/null 2>&1 && npm install -g box-js) \
    || (echo "ERROR: box-js missing and npm unavailable" >&2 && false) \
    && box-js --help >/dev/null 2>&1

# Create venv on the base image's Python 3.12
RUN python3 -m venv /opt/matt/venv
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
# unsatisfied **core** dependencies (matt.py prints "Missing required
# packages" for those). Optional misses (eg. lang) are OK and ignored.
RUN matt --check 2>&1 | tee /tmp/matt-check.log \
    && ! grep -q "Missing required packages" /tmp/matt-check.log

# Switch back to remnux user
USER remnux
WORKDIR /data

CMD ["/bin/bash"]
