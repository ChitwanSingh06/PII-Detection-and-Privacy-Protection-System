FROM python:3.11.2-slim


WORKDIR /app
COPY anonymizer ./anonymizer
COPY pb ./pb
COPY requirements.txt .

ENV http_proxy=http://hpeproxy.its.hpecorp.net:443
ENV https_proxy=http://hpeproxy.its.hpecorp.net:443

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python3", "-m", "anonymizer" ]