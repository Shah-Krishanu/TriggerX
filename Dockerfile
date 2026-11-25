FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
COPY data/honeypots.txt /app/honeypots.txt
ENV PYTHONUNBUFFERED=1
