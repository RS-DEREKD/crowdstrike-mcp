FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd -r -s /bin/false mcp
COPY . .
USER mcp
EXPOSE 8000
ENTRYPOINT ["python", "server.py", "--transport", "streamable-http", "--host", "0.0.0.0"]
