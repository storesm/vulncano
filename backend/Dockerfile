FROM python:3.11-slim

# weasyprint renders the pdf reports and needs the pango stack at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libcairo2 libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY vulncano ./vulncano
RUN pip install --no-cache-dir -e ".[mysql,pdf]"

COPY fixtures ./fixtures

ENV VULNCANO_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "vulncano.main:app", "--host", "0.0.0.0", "--port", "8000"]
