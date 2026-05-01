FROM python:3.12-slim

LABEL org.opencontainers.image.title="IIM Workbench"
LABEL org.opencontainers.image.description="Local workspace for building, validating, visualizing, importing, and exporting IIM chains, patterns, and feeds."
LABEL org.opencontainers.image.source="https://github.com/MalwareboxEU/IIM-Workbench"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV IIM_CATALOG=/app/techniques/iim-techniques-v1.0.json

WORKDIR /app

RUN addgroup --system iim && adduser --system --ingroup iim --home /app iim

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN chown -R iim:iim /app

USER iim

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3).read()" || exit 1

CMD ["python", "iim_workbench.py", "--host", "0.0.0.0", "--port", "5000"]
