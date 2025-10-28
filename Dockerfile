# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/opt/tornadoai \
    PIP_BREAK_SYSTEM_PACKAGES=1

# Install system dependencies and security tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
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
        burpsuite \
        libimobiledevice-utils \
        usbmuxd \
        ifuse \
        ideviceinstaller \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install pip based tooling (advanced mobile / iOS helpers)
RUN python3 -m pip install --no-cache-dir --upgrade pip \
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
