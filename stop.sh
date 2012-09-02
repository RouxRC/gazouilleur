#!/bin/bash

BOTENV=`grep BOTENV= start.sh  | sed 's/^.*=//'`
LOCK=/tmp/$BOTENV.lock

process=`ps x | grep 'python bot.py' | grep -v grep | sed 's/ .*$//'`
if test -e $LOCK && not test -z $process; then
  kill $process
else
  echo "The bot doesn't seem like running."
fi
rm -f $LOCK
