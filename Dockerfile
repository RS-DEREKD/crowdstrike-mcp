FROM python:3.12-slim
WORKDIR /app
COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
RUN useradd -r -s /bin/false mcp
USER mcp
EXPOSE 8000
ENTRYPOINT ["crowdstrike-mcp", "--transport", "streamable-http", "--host", "0.0.0.0"]
