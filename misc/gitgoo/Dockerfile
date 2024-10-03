FROM python:3.10
RUN pip install flask gunicorn

WORKDIR /app

COPY flag.txt index.html app.py ./
COPY dotgitignore .gitignore
COPY dotgit .git
COPY Dockerfile.dist Dockerfile

CMD gunicorn app:app --bind 0.0.0.0:5000
