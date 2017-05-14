#!/bin/bash
# Send by email digest log of an IRC chan (removes the bot's messages)
#
# USAGE: bin/weekly_mail.sh [ <CHAN> [<EMAIL> [<STARTDATE>]]]
# Set in gazouilleur/config.py which <DEFAULT_EMAIL> will be sent to when not set in option
# Then set in a crontab:
# 30 03 * * * bash /home/gazouilleur/gazouilleur2/bin/weekly_mail.sh

cd "$(dirname $0)"/..
BOTPATH=$(pwd)
CONFIGFILE=$BOTPATH/gazouilleur/config.py
DEFAULT_EMAIL=$(grep 'DEFAULT_EMAIL=' $CONFIGFILE | tail -n 1 | sed "s/^.*=['\"]\([^'\"]\+\)['\"].*$/\1/")

CHAN="#"$1
if [ "$CHAN" == "#" ]; then
  CHAN="#"$(grep "['\"]\s*:\s*{\s*$" $CONFIGFILE | head -n 1 | sed "s/^\s*['\"]\([^'\"]\+\)['\"].*$/\1/")
fi

EMAILDEST=$2
if [ -z "$EMAILDEST" ]; then
  if [ -z "$DEFAULT_EMAIL" ]; then
    echo "Please provide an email in argument or set DEFAULT_EMAIL into gazouilleur/config.py"
    exit 1
  fi
  EMAILDEST=$DEFAULT_EMAIL
fi

DATE=$3
if [ -z "$DATE" ]; then
  DATE=$(date -d 'last-week' '+%Y-%m-%d')
fi

DEBUG=false
if [ ! -z "$4" ]; then
  DEBUG=true
fi

BOT=$(grep ^BOTNAME $CONFIGFILE | sed "s/^.*['\"]\([^'\"]\+\)['\"].*$/\1/")

LOGPATH=$BOTPATH/log/${BOT}_${CHAN}.log
TMPPATH="/tmp/${BOT}-$CHAN.tmp"
if test -f "$LOGPATH.1"; then
  cat "$LOGPATH.1" "$LOGPATH" > "$TMPPATH"
  if test -f "$LOGPATH.2"; then
    cp "$TMPPATH" "$TMPPATH".tmp
    cat "$LOGPATH.2" "$TMPPATH".tmp > "$TMPPATH"
    rm "$TMPPATH".tmp
  fi
  LOGPATH="$TMPPATH"
fi

MAX_CHAR=150

NBLINE=$(wc -l $LOGPATH | sed 's/ .*//')
BEGINLINE=$(grep -n "^$DATE" $LOGPATH | head -n 1 | sed 's/:.*//')
TAILLINE=$(( $NBLINE - $BEGINLINE + 5))
tail -n $TAILLINE $LOGPATH |
  grep -v "[0-9][0-9]:[0-9][0-9]:[0-9][0-9] ${BOT}: " |
  grep -v "[0-9][0-9]:[0-9][0-9]:[0-9][0-9] \S\+: \[.* joined\]$" |
  grep -v "[0-9][0-9]:[0-9][0-9]:[0-9][0-9] \S\+: \[.* left.*\]$" |
  sed 's/\([0-9][0-9]:[0-9][0-9]:[0-9][0-9] \S\+\)!\S\+@\S\+:/\1:/' |
  sed 's/^/ /' |
  fold -w $MAX_CHAR -s |
  sed 's/^\([^ ]\)/                   \1/' > /tmp/email_log.txt
if $DEBUG; then
  cat /tmp/email_log.txt
else
  CLEANCHAN=$(echo $CHAN | sed 's/[^0-9a-z]//g')
  URLGAZOU=$(grep "^URL_STATS" gazouilleur/config.py | head -1 | sed 's/^.*=\s*"//' | sed 's/\/\?".*$//')
  HTMLFILE="weekly_irclog_$CLEANCHAN.html"
  OUTPUT="web/$HTMLFILE"
  echo "<html><body>" > $OUTPUT
  cat /tmp/email_log.txt | sed -r 's/(https?:\S+)/<a href="\1">\1<\/a>/g' | sed 's/^ 20/<br>20/' >> $OUTPUT
  echo "</body></html>" >> $OUTPUT
  echo "$URLGAZOU/$HTMLFILE" > /tmp/email_log_full.txt
  echo >> /tmp/email_log_full.txt
  cat /tmp/email_log.txt >> /tmp/email_log_full.txt
  echo >> /tmp/email_log_full.txt
  echo "--" >> /tmp/email_log_full.txt
  echo "Envoyé par $0 via la crontab de l'utilisateur gazouilleur" >> /tmp/email_log_full.txt
  cat /tmp/email_log_full.txt | iconv -c -f UTF-8 -t ISO-8859-1 | mail -s "[$BOT] IRC weekly summary for $CHAN since $DATE" $EMAILDEST
fi

rm -f "$TMPPATH"
