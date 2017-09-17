#!/bin/bash
# Save pad in logs into a git repository
#
# USAGE: bin/daily_save_framapad.sh [ <GIT_REPOSITORY_PATH> <CHAN> [<STARTDATE>]]
# Then set in a crontab:
# 30 03 * * * bash /home/gazouilleur/gazouilleur2/bin/daily_save_framapad.sh /path/to/your/repository_git

cd "$(dirname $0)"/..
BOTPATH=$(pwd)
CONFIGFILE=$BOTPATH/gazouilleur/config.py
BOT=$(grep ^BOTNAME $CONFIGFILE | sed "s/^.*['\"]\([^'\"]\+\)['\"].*$/\1/")
BASE_PAD_URL="https://[a-zA-Z]+\.framapad\.org/p/"

REPO_PATH=$1
if [ -z "$REPO_PATH" ]; then
    echo "Git path repository must be defined"
    exit
fi

CHAN="#"$2
if [ "$CHAN" == "#" ]; then
  CHAN="#"$(grep "['\"]\s*:\s*{\s*$" $CONFIGFILE | head -n 1 | sed "s/^\s*['\"]\([^'\"]\+\)['\"].*$/\1/")
fi

DATE=$3
if [ -z "$DATE" ]; then
  DATE=$(date -d 'yesterday' '+%Y-%m-%d')
fi


LOGPATH=$BOTPATH/log/${BOT}_${CHAN}.log
TMPPATH="/tmp/${BOT}-$CHAN.tmp"
if test -f "$LOGPATH.1"; then
  cat "$LOGPATH.1" "$LOGPATH" > "$TMPPATH"
  LOGPATH="$TMPPATH"
fi

cd $REPO_PATH > /dev/null
git pull 2> /dev/null
cd - > /dev/null

NBLINE=$(wc -l $LOGPATH | sed 's/ .*//')
BEGINLINE=$(grep -n "^$DATE" $LOGPATH | head -n 1 | sed 's/:.*//')
TAILLINE=$(( $NBLINE - $BEGINLINE + 5))
tail -n $TAILLINE $LOGPATH | grep -Eo "$BASE_PAD_URL[éàèêùûâ;a-zA-Z0-9_-,\"]+" | sort | uniq | while read URL
do
    REF_PAD=$(echo $URL | sed -r "s|$BASE_PAD_URL||")
    PATH_PAD_TMP=$REPO_PATH/$REF_PAD.txt.tmp
    curl -s $URL/export/txt > $PATH_PAD_TMP
    if [ $(head -n 1 $PATH_PAD_TMP | grep "––––– Ce texte est à effacer (après lecture si c’est votre première visite) ou à conserver en bas de votre pad –––––" | wc -l) == 1 ]
    then
        rm $PATH_PAD_TMP
        echo "Pad ignoré $URL"
        continue
    fi

    if [ $(head -n 1 $PATH_PAD_TMP | grep "Le contenu de ce pad a été effacé" | wc -l) == 1 ]
    then
        rm $PATH_PAD_TMP
        echo "Pad ignoré $URL"
        continue
    fi

    if [ $(cat $PATH_PAD_TMP | sed 's/ //g' | grep -Ev "^$" | wc -l) == 0 ]
    then
        rm $PATH_PAD_TMP
        echo "Pad ignoré $URL"
        continue
    fi

    if ! test -f "$PATH_PAD_TMP"; then
        echo "Pad ignoré $URL"
        continue
    fi

    cat $PATH_PAD_TMP > $REPO_PATH/$REF_PAD.txt
    rm $PATH_PAD_TMP
    echo "Sauvegarde du pad : $URL"
    echo "---" > $REPO_PATH/$REF_PAD.md
    echo "title: $(cat $REPO_PATH/$REF_PAD.txt | head -n 1)" >> $REPO_PATH/$REF_PAD.md
    echo "url: $URL" >> $REPO_PATH/$REF_PAD.md
    echo "---" >> $REPO_PATH/$REF_PAD.md
    curl -s $URL/export/markdown >> $REPO_PATH/$REF_PAD.md
    cd $REPO_PATH > /dev/null
    git add $REF_PAD.txt > /dev/null
    git add $REF_PAD.md > /dev/null
    cd - > /dev/null
done

cd $REPO_PATH > /dev/null
git commit -m "Mise à jour automatique des pads depuis gazouilleur" > /dev/null
git push 2> /dev/null
cd - > /dev/null
