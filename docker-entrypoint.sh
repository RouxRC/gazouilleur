#!/bin/bash

# fill web directory from web.sample if not exists
if ! test -d /app/web; then
  cp -r /app/web{.sample,}
fi

bash bin/configureDB-mongo3.sh

python /app/gazouilleur/bot.py
