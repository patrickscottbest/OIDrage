FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    IPADDRESS=0.0.0.0 \
    PORT=1161

WORKDIR /app

RUN useradd --create-home --uid 10001 oidrage

COPY OIDrage.py ieee754.py __init__.py mimic.txt ./
COPY asn1 ./asn1

RUN chown -R oidrage:oidrage /app

USER oidrage

EXPOSE 1161/udp

CMD ["python3", "./OIDrage.py"]
