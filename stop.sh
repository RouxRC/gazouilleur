#!/bin/bash

BOTENV=`grep BOTENV= start.sh  | sed 's/^.*=//'`
LOCK="/tmp/$BOTENV.lock"

if [ -e $LOCK ]; then
  master=`cat $LOCK`
  process=`ps x -f | grep 'python bot.py' | grep -v grep | grep "$master" | awk -F " " '{print $2}'`
  if [ ! -z $process ]; then
    echo "Stopping the bot"
    kill $process
    rm -f $LOCK
    exit
  fi
fi

echo "The bot doesn't seem like running."

