from python:3.11-slim

# Set working directory
WORKDIR /app

COPY ./requirements.txt /app/

RUN pip install -r requirements.txt

COPY ./*.py /app/
COPY ./common-0.1.0-py3-none-any.whl /app/

RUN pip install /app/common-0.1.0-py3-none-any.whl

EXPOSE 8080

CMD ["python", "app.py"]