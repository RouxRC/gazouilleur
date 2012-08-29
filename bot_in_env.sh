#!/bin/bash

#Sample script file to run the bot automatically as service within a vritualenv preset
BOTENV=gazouilleur
PATH=$HOME/gazouilleur2

#LOCK
LOCK="/tmp/gazouilleur.lock"
if test -e $LOCK ; then
  exit
fi
touch $LOCK
cd $PATH
export WORKON_HOME=$HOME/virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
workon $BOTENV
python bot.py > run.log 2>&1
rm $LOCK

