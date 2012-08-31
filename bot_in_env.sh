#!/bin/bash

#Sample script file to run the bot automatically as service within a vritualenv preset
BOTENV=gazouilleur
BOTPATH=$HOME/gazouilleur2

#LOCK
LOCK="/tmp/$BOTENV.lock"
if test -e $LOCK ; then
  exit
fi
touch $LOCK
cd $BOTPATH
export WORKON_HOME=$HOME/virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
workon $BOTENV
python bot.py > run.log 2>&1
rm $LOCK

