FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV AFH_DATA_DIR=/data AFH_HOST=0.0.0.0 AFH_PORT=8000 AFH_TRUST_PROXY=1
VOLUME /data
EXPOSE 8000
CMD ["python", "run.py"]
