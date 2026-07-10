FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "psycopg[binary]" requests
COPY worker.py .
CMD ["python", "-u", "worker.py"]
