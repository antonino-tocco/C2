FROM python:3.12-slim

WORKDIR /app

# Build tools for native implant compilation
# g++, strip, libcurl-dev, libssl-dev for Linux C++ builds
# dotnet SDK for Windows .NET builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    binutils \
    libcurl4-openssl-dev \
    libssl-dev \
    libicu-dev \
    wget \
    && wget https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 9.0 --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm /tmp/dotnet-install.sh \
    && apt-get purge -y wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/ /app/backend/

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "backend.classes.servers.http_server:app", "--host", "0.0.0.0", "--port", "8000"]
