#!/bin/bash

git stash
git pull > /tmp/gazouilleur-pull.log 2>&1
git stash pop
if grep "requirements.txt" /tmp/gazouilleur-pull.log; then
  bin/update_requirements.sh
fi
bin/configure.sh
if grep "gazouilleur/config.py.example" /tmp/gazouilleur-pull.log; then
  echo "gazouilleur/config.py.example was modified. You may want to check for new options, update your config.py and restart again."
fi
rm -f /tmp/gazouilleur-pull.log
bin/gazouilleur restart
