#!/bin/bash

source $(which virtualenvwrapper.sh)
workon gazouilleur

git diff | grep "^[+\-]" > /tmp/diffctrl
while true; do
  git diff | grep "^[+\-]" > /tmp/diffctrl2
  if diff /tmp/diffctrl{,2} | grep .; then
    echo "rebuilding..."
    mv -f /tmp/diffctrl{2,}
    ls web/monitor | sed 's/+/ /g' | while read page; do
      python -c 'from gazouilleur.lib.webmonitor import WebMonitor as wm; wm("'"$page"'", "").build_diff_page()'
      echo "...$page done"
    done
    echo
  fi
  sleep 1
done
