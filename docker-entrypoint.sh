#!/bin/bash

if ! test -d /app/web/templates; then
  for d in templates css fonts js; do
    cp -r /app/web.sample/$d /app/web/$d
  done
fi

cd /app

bash bin/configureDB-mongo3.sh

python gazouilleur/bot.py
