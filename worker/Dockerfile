FROM python:3.12-slim
WORKDIR /app

# psycopg[binary] = sterownik Postgresa dla Pythona (gotowe binarki, bez kompilacji).
RUN pip install --no-cache-dir "psycopg[binary]" requests

COPY worker.py .

# -u = niebuforowane wyjście, żeby logi pojawiały się od razu.
CMD ["python", "-u", "worker.py"]
