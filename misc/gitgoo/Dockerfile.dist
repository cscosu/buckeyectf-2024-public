FROM python:3.10
RUN pip install flask gunicorn

WORKDIR /app

COPY ./ ./

CMD gunicorn app:app --bind 0.0.0.0:5000
