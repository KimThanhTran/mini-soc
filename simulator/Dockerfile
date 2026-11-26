# Build from the repository root: docker build -f simulator/Dockerfile .
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home sim
WORKDIR /srv
COPY sensors/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/ship.py backend/app/simulation.py simulator/simulate.py ./
USER sim
CMD ["python", "simulate.py"]
