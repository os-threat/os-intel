FROM python:3.10 as base

WORKDIR /app

COPY requirements.txt requirements.txt
COPY test_connection.py test_connection.py

RUN pip install --upgrade pip && pip install -r requirements.txt

CMD ["python3","test_connection.py"]
