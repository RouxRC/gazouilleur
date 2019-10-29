FROM python:2.7.17-alpine3.9

WORKDIR /app

ENV PYTHONPATH $PYTHONPATH:/app

COPY requirements.txt /app/requirements.txt

RUN apk --update add build-base gfortran pkgconfig python-dev openblas-dev freetype-dev libpng-dev libxml2-dev libxslt-dev libffi-dev openssl-dev mongodb \
    && ln -s /usr/include/locale.h /usr/include/xlocale.h \
    && pip install --cache-dir=/tmp/pipcache --upgrade setuptools pip \
    && pip install --cache-dir=/tmp/pipcache numpy==1.7.1 \
    && pip install --cache-dir=/tmp/pipcache matplotlib==1.5.3 pystache==0.5.3 Wand==0.4.4 \
    && pip install --cache-dir=/tmp/pipcache --requirement /app/requirements.txt \
    && rm -r /tmp/pipcache \
    && apk del build-base gfortran pkgconfig \
    && rm -r /var/cache/apk/*

COPY ./bin /app/bin

COPY ./gazouilleur /app/gazouilleur

COPY ./gazouilleur/config-docker.py /app/gazouilleur/config.py

COPY ./docker-entrypoint.sh /app/docker-entrypoint.sh

COPY ./web /app/web.sample

RUN mkdir /app/cache /app/log

RUN chmod +x /app/docker-entrypoint.sh

RUN mkdir -p /root/.config/matplotlib && echo "backend : Agg" > /root/.config/matplotlib/matplotlibrc

VOLUME ["/app/web", "/app/log"]

ENTRYPOINT ["sh", "/app/docker-entrypoint.sh"]
