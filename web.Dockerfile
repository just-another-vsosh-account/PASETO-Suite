FROM python:3.11-alpine

COPY . /app
WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev && \
    pip install flask cryptography PyNaCl argon2-cffi

EXPOSE 8000

CMD ["python", "sitewrap.py"]