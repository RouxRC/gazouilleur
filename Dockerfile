FROM python:2.7

WORKDIR /app

ENV PYTHONPATH $PYTHONPATH:/app

COPY requirements.txt /app/requirements.txt

RUN apt-get update \
    && apt-get install curl git vim python-dev python-pip libxml2-dev libfreetype6-dev libpng-dev libxslt1-dev libffi-dev mongodb -y --no-install-recommends \
    && pip install --cache-dir=/tmp/pipcache --upgrade setuptools pip \
    && pip install --cache-dir=/tmp/pipcache numpy==1.7.1 \
    && pip install --cache-dir=/tmp/pipcache matplotlib==1.3.0 pystache==0.5.3 Wand==0.4.4 \
    && pip install --cache-dir=/tmp/pipcache --requirement /app/requirements.txt \
    && rm -r /tmp/pipcache \
    && apt-get autoclean \
    && rm -r /var/cache/apt/*

COPY ./bin /app/bin

COPY ./gazouilleur /app/gazouilleur

COPY ./gazouilleur/config-docker.py /app/gazouilleur/config.py

COPY ./docker-entrypoint.sh /app/docker-entrypoint.sh

COPY ./web /app/web.sample

RUN mkdir /app/cache /app/log

RUN chmod +x /app/docker-entrypoint.sh

RUN mkdir -p /root/.config/matplotlib && echo "backend : Agg" > /root/.config/matplotlib/matplotlibrc

VOLUME ["/app/web"]

ENTRYPOINT ["/app/docker-entrypoint.sh"]
