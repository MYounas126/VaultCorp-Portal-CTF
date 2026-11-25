FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils iputils-ping curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/entrypoint.sh && \
    mkdir -p /opt/flags && \
    mkdir -p /app/uploads && chmod 755 /app/uploads

EXPOSE 5000

CMD ["/app/entrypoint.sh"]
