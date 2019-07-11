#!/bin/bash

if ! test -f "gazouilleur/config.py"; then
  echo "ERROR: Could not find \`gazouilleur/config.py\`."
  echo "ERROR: Please run \`bash bin/configure.sh\` to create it, then edit it to prepare your bot."
  exit 1
fi

cd gazouilleur
MONGO_CONF=$(python -c 'import config; print "%s;%s;%s;%s;%s" % (config.MONGODB["DATABASE"], config.MONGODB["HOST"], config.MONGODB["PORT"], config.MONGODB["USER"], config.MONGODB["PSWD"])')
if test -z "$MONGO_CONF"; then
  echo "ERROR: Could not read \`gazouilleur/config.py\`."
  echo "ERROR: Please edit it to fix the syntax issue above."
  exit 1
fi
cd ..

MONGO_DB=$(echo $MONGO_CONF | awk -F ";" '{print $1}')
MONGO_HOST=$(echo $MONGO_CONF | awk -F ";" '{print $2}')
MONGO_PORT=$(echo $MONGO_CONF | awk -F ";" '{print $3}')
MONGO_USER=$(echo $MONGO_CONF | awk -F ";" '{print $4}')
MONGO_PASS=$(echo $MONGO_CONF | awk -F ";" '{print $5}')

existing=$(mongo --quiet --host $MONGO_HOST:$MONGO_PORT $MONGO_DB --eval "db.getUsers().length")

if [ "$existing" = "0" ]; then
  echo "Configuring database $MONGO_DB on $MONGO_HOST:$MONGO_PORT with user $MONGO_USER and pass $MONGO_PASS"
  echo -e "use $MONGO_DB\ndb.createUser({user: \"$MONGO_USER\", pwd: \"$MONGO_PASS\", roles: ['userAdmin']})" | mongo --host "$MONGO_HOST:$MONGO_PORT"
fi
