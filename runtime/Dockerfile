FROM python:3.9.25-slim-bookworm@sha256:a02e9c5406c416c504d6c9a1a306ff4080c3173f1008d192f953bd20382a2d5c
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CERT=/etc/ssl/certs/ca-certificates.crt SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge '20250419~deb12u2' \
    && rm -rf /var/lib/apt/lists/*
COPY tls_check.py /opt/tls_check.py
RUN python -I /opt/tls_check.py > /opt/tls-check.json
COPY requirements.txt /opt/requirements.txt
RUN python -m pip install --no-cache-dir --no-compile --only-binary=:all: --require-hashes -r /opt/requirements.txt \
    && python -c "import sys,mpmath; assert sys.version_info[:3]==(3,9,25); assert mpmath.__version__=='1.3.0'" \
    && dpkg-query -W > /opt/packages.txt
USER 65532:65532
WORKDIR /tmp
CMD ["python", "--version"]
