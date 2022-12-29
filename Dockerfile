FROM python:3.9-slim
WORKDIR /app
EXPOSE 161/udp
COPY  . .
CMD ["python3", "./OIDrage.py"]