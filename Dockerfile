FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml requirements.lock ./
COPY src ./src
RUN pip install --no-cache-dir -r requirements.lock && pip install --no-cache-dir --no-deps . && rm -rf build src/*.egg-info && useradd --create-home app && mkdir -m 700 .dev-mail && chown app:app .dev-mail
COPY alembic.ini ./
COPY migrations ./migrations
COPY docs/openapi.json ./docs/openapi.json
USER app
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "/dev/null", "auth_service:create_app()"]
