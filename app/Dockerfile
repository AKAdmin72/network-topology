FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends snmp curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Download vis-network locally so the app works without internet access
RUN mkdir -p static && \
    curl -sL https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js -o static/vis-network.min.js && \
    curl -sL https://unpkg.com/vis-network@9.1.9/styles/vis-network.min.css -o static/vis-network.min.css
COPY . .
CMD ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8080"]
