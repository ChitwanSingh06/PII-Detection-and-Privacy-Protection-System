FROM python:3.11-slim

WORKDIR /app

COPY . /app

ENV http_proxy=http://hpeproxy.its.hpecorp.net:443
ENV https_proxy=http://hpeproxy.its.hpecorp.net:443

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "pii_analyser.py"]