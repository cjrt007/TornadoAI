# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/opt/tornadoai

# Install system dependencies and security tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        git \
        curl \
        build-essential \
        libssl-dev \
        libffi-dev \
        nmap \
        nuclei \
        sqlmap \
        jadx \
        apktool \
        mobsf \
        frida-tools \
        objection \
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

WORKDIR ${APP_HOME}

COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
