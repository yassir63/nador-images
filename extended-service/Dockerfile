FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir prometheus-client==0.21.1 requests==2.32.5
WORKDIR /app
COPY extended-service/*.py /app/
COPY common/active_checks.py /app/
CMD ["python3", "/app/service_probe.py"]
