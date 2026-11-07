# Base: published v1.0.1-standard; preserve its calculator dependencies.
FROM python:3.10.20-slim-trixie@sha256:bc2021edaa0ed48c55ccf295efeed3922147736c6a9f179e0c3b741e96d45fbc

WORKDIR /exporter
COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir -r requirements.txt && python3 -m pip check
COPY LICENSE.upstream ./
COPY kpi_calculator.py /exporter/kpi_calculator.py

EXPOSE 9000
CMD ["python3", "kpi_calculator.py"]
