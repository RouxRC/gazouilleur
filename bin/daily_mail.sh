#!/bin/bash
# Send by email logs of an IRC chan
#
# v0.1 : 2010-10-18 ; teymour for supybot
# v0.2 : 2012-08-25 ; Roux for gazouilleur
# v0.3 : 2014-03-02 ; Roux optionnalize
#
# USAGE: bin/daily_mail.sh [ <CHAN> [<STARTDATE> [<EMAIL>]]]
# Set below which <DEFAULT_EMAIL> will be sent to when not set in option
# To be set in a crontab 
# 30 03 * * * bash /home/gazouilleur/gazouilleur2/bin/daily_mail.sh
# @reboot     bash /home/gazouilleur/gazouilleur2/bin/gazouilleur start --nologs

cd "$(dirname $0)"/..
BOTPATH=$(pwd)
DEFAULT_EMAIL="example@example.com"

CHAN="#"$1
if [ "$CHAN" == "#" ]; then
  CHAN="#"$(grep "['\"]\s*:\s*{\s*$" $BOTPATH/gazouilleur/config.py | head -n 1 | sed "s/^\s*['\"]\([^'\"]\+\)['\"].*$/\1/")
fi

DATE=$2
if [ -z "$DATE" ]; then
  DATE=$(date -d 'yesterday' '+%Y-%m-%d')
fi

EMAILDEST=$3
if [ -z "$EMAILDEST" ]; then
  EMAILDEST=$DEFAULT_EMAIL
fi

DEBUG=false
if [ ! -z "$4" ]; then
  DEBUG=true
fi

BOT=$(grep ^BOTNAME $BOTPATH/gazouilleur/config.py | sed "s/^.*['\"]\([^'\"]\+\)['\"].*$/\1/")

LOGPATH=$BOTPATH/log/${BOT}_${CHAN}.log
TMPPATH="/tmp/${BOT}-$CHAN.tmp"
if test -f "$LOGPATH.1"; then
  cat "$LOGPATH.1" "$LOGPATH" > "$TMPPATH"
  LOGPATH="$TMPPATH"
fi

MAX_CHAR=150

NBLINE=$(wc -l $LOGPATH | sed 's/ .*//')
BEGINLINE=$(grep -n "^$DATE" $LOGPATH | head -n 1 | sed 's/:.*//')
TAILLINE=$(( $NBLINE - $BEGINLINE + 5))
tail -n $TAILLINE $LOGPATH | sed 's/^/ /' | fold -w $MAX_CHAR -s | sed 's/^\([^ ]\)/                   \1/' > /tmp/email_log.txt
echo "" >> /tmp/email_log.txt
echo "--" >> /tmp/email_log.txt
echo "Envoyé par $0 via la crontab de l'utilisateur gazouilleur" >> /tmp/email_log.txt
if $DEBUG; then
  cat /tmp/email_log.txt
else
  cat /tmp/email_log.txt | iconv -c -f UTF-8 -t ISO-8859-1 | mail -s "[$BOT] IRC log $CHAN since $DATE" $EMAILDEST
fi

rm -f "$TMPPATH"
