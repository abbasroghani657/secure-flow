FROM python:3.11-slim

# System deps kept minimal; curl/unzip only needed if you enable Nuclei below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional: install the Linux Nuclei binary to enable "Deep scan" in the container.
# The built-in scanner works without this. Uncomment to enable:
# RUN curl -sSL -o /tmp/nuclei.zip \
#     https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_amd64.zip \
#     && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin && rm /tmp/nuclei.zip
# ENV NUCLEI_PATH=/usr/local/bin/nuclei

COPY . .
RUN chmod +x docker-entrypoint.sh

EXPOSE 8077
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8077", "--no-server-header"]
