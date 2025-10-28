# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/opt/tornadoai \
    PIP_BREAK_SYSTEM_PACKAGES=1

# Refresh Kali apt sources to a known-good mirror before installing tooling
RUN printf 'deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware\n' \
        > /etc/apt/sources.list

# Install system dependencies and security tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        python3-wheel \
        git \
        curl \
        wget \
        unzip \
        ca-certificates \
        build-essential \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        libjpeg62-turbo-dev \
        zlib1g-dev \
        openjdk-17-jdk \
        nmap \
        nuclei \
        sqlmap \
        jadx \
        apktool \
        dirb \
        whatweb \
        ffuf \
        wfuzz \
        masscan \
        libimobiledevice-utils \
        usbmuxd \
        ifuse \
        ideviceinstaller \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ARG BURP_VERSION=2024.5.1
RUN mkdir -p /opt/tools/burpsuite \
    && curl -L --output /opt/tools/burpsuite/burpsuite.jar "https://portswigger.net/burp/releases/download?product=community&version=${BURP_VERSION}&type=Jar" \
    && printf '#!/bin/bash\nexec java -jar /opt/tools/burpsuite/burpsuite.jar "$@"\n' > /usr/local/bin/burpsuite \
    && chmod +x /usr/local/bin/burpsuite

# Upgrade pip tooling and install packages that Kali does not provide via apt
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python3 -m pip install --no-cache-dir \
        frida-tools \
        objection \
        reflutter \
        idb-companion

# Pull additional tooling that is not available via apt repositories
RUN mkdir -p /opt/tools \
    && git clone --depth 1 https://github.com/MobSF/Mobile-Security-Framework-MobSF.git /opt/tools/mobsf \
    && python3 -m pip install --no-cache-dir -r /opt/tools/mobsf/requirements.txt \
    && rm -rf /opt/tools/mobsf/.git

WORKDIR ${APP_HOME}

COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
