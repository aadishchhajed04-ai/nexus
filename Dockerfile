FROM python:3.12-slim

# nmap is installed here because the collector shells out to the real
# binary — it is NOT a pip package. capa is NOT installed here: it
# needs its rules repository fetched separately and is meant to be run
# against specific authorized samples, not baked into a base image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000 9090
ENV NEXUS_API_TOKEN=dev-token-change-me

CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
