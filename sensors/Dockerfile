FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home sensor
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ship.py ssh_honeypot.py web_honeypot.py ./
USER sensor
CMD ["python", "ssh_honeypot.py"]
