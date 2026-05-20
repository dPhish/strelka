# Base and setup configuration
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# User configuration
ARG CONFIG_TESTS=false
ARG SCANNER_TESTS=false
ARG SCANNER_TEST=""

# Stable versions
ARG YARA_VERSION=4.3.2
ARG EXIFTOOL_VERSION=12.76

# Environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PYTHONUNBUFFERED 1

# User configuration
ARG USERNAME=strelka
ARG USER_UID=1001
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME

RUN rm -f /etc/apt/apt.conf.d/docker-clean; \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install build packages
RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
    automake build-essential cmake curl gcc git dirmngr gnupg gpg \
    libglu1-mesa libtool make swig python3-dev python3-pip python3-wheel \
    python-is-python3 pkg-config supervisor ncat ca-certificates autoconf xz-utils \
    perl wget unzip

# Install Zeek
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' > /etc/apt/sources.list.d/zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg && \
    apt-get update -q && \
    apt-get install -y --no-install-recommends zeek-lts
ENV PATH=$PATH:/opt/zeek/bin

# Install runtime packages
RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
    antiword binwalk libarchive-dev libfuzzy-dev libjansson-dev \
    libmagic-dev libssl-dev libzbar0 libgl1 redis-server suricata \
    tesseract-ocr unrar unzip upx jq p7zip-full && \
    test -f /opt/zeek/bin/zeek && cp /opt/zeek/bin/zeek /bin/zeek || true && \
    rm -rf /opt/zeek/share/btest /opt/zeek/bin /opt/zeek/lib/*.a

# Install ExifTool
RUN cd /tmp && \
    curl -fsSLO https://github.com/exiftool/exiftool/archive/refs/tags/${EXIFTOOL_VERSION}.tar.gz && \
    tar -xzf ${EXIFTOOL_VERSION}.tar.gz && \
    cd exiftool-${EXIFTOOL_VERSION} && \
    perl Makefile.PL && \
    make && \
    make install

# Install YARA
RUN cd /tmp && \
    curl -fsSLO https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz && \
    tar -xzf v${YARA_VERSION}.tar.gz && \
    cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-magic --enable-cuckoo && \
    make && \
    make install && \
    ldconfig

# Install yara-python (FIXED)
RUN pip install yara-python

# Install Google Chrome
RUN curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google.list && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends google-chrome-stable

ENV ROD_BROWSER_PATH=/usr/bin/google-chrome
ENV CHROME_PATH=/usr/bin/google-chrome

COPY configs/python/backend/suricata/suricata.yaml /etc/suricata/suricata.yaml

# Install httpx CLI
RUN cd /tmp && \
    wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && \
    unzip httpx_1.6.9_linux_amd64.zip httpx && \
    mv httpx /usr/local/bin/httpx_tmp && \
    chmod +x /usr/local/bin/httpx_tmp && \
    rm httpx_1.6.9_linux_amd64.zip

# Install JTR deps
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    zlib1g-dev yasm libgmp-dev liblzma-dev libpcap-dev libbz2-dev libgomp1 && \
    cpan -i Compress::Raw::Lzma

# Build JTR
RUN mkdir /jtr && cd /jtr && \
    git init && \
    git remote add origin https://github.com/openwall/john.git && \
    git fetch --depth 1 origin b5c10480f56ff1b5d76c6cbdaf9c817582ee2228 && \
    git reset --hard FETCH_HEAD && \
    rm -rf .git && \
    cd src && \
    ./configure && \
    make -s clean && \
    make -sj4 && \
    make install && \
    cp -Tr /jtr/run/ /jtr && rm -rf /jtr/run && \
    chmod -R 777 /jtr && \
    chown -R $USER_UID:$USER_UID /jtr

# ClamAV
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    clamav clamav-base clamav-daemon clamav-freshclam

RUN touch /var/log/clamav/freshclam.log && \
    chmod 777 /var/log/clamav/freshclam.log && \
    chown clamav /var/log/clamav/freshclam.log && \
    chown 1001:1001 /var/lib/clamav

# Python deps
RUN python3 -m pip install -U pip setuptools==75.8.1 && \
    pip install poetry==2.2.1 wheel six pyasn1==0.4.8 && \
    pip install --no-build-isolation ssdeep && \
    rm -rf /root/.cache/pip

WORKDIR /strelka/
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && \
    poetry lock && \
    poetry install --only main && \
    rm -rf /root/.cache/pypoetry

COPY ./src/python/ /strelka/
COPY ./configs/python/backend/ /etc/strelka/

RUN pip install kafka-python

# Install app
RUN cd /strelka && \
    python3 setup.py build && \
    python3 setup.py install && \
    python3 setup.py clean --all && \
    rm -rf dist/ strelka.egg-info && \
    mkdir -p /var/log/strelka && \
    chgrp -R 0 /var/log/strelka && \
    chmod -R g=u /var/log/strelka

USER $USERNAME

RUN echo '[+] Run build checks' && \
    cd /strelka/strelka && \
    if $SCANNER_TESTS; then python3 -m pytest -p no:cacheprovider -s tests/$SCANNER_TEST; fi && \
    if $CONFIG_TESTS; then python3 -m pytest -s tests_configuration/; fi && \
    echo '[+] Done'

USER root

RUN rm -rf /strelka /root/.cache /tmp/* && \
    rm -rf /etc/strelka/

USER $USERNAME
