FROM python:3.11.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir .

ENTRYPOINT ["repo-shield"]
CMD ["."]