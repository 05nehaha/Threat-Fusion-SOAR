FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=5000

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nmap git perl ca-certificates \
    libjson-perl libxml-writer-perl libnet-ssleay-perl libio-socket-ssl-perl && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    printf '#!/bin/sh\nexec /usr/bin/perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .
RUN mkdir -p /app/scans/reports

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "900", "--graceful-timeout", "60", "app:app"]
