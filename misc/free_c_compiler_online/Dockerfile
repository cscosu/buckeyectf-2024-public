FROM quay.io/podman/stable
RUN dnf install -y python3 python3-pip

RUN curl http://bctf-24-stage1.s3.amazonaws.com/gcc.tar.gz -o gcc.tar.gz
RUN gunzip gcc.tar.gz

RUN useradd -m appuser
WORKDIR /app

COPY requirements.txt ./
RUN python3 -m pip install -r requirements.txt

COPY app.py ./
COPY flag.txt ./
COPY templates templates

RUN chown -R appuser:appuser /app

USER appuser

CMD gunicorn app:app --bind 0.0.0.0:5000
