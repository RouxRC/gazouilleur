#!/bin/bash

echo "Configure..."
echo "------------"
for file in gazouilleur/config.py; do
  if ! test -f "$file"; then
    echo " preparing $file from example"
    sed "s|##GAZOUILLEURPATH##|"`pwd`"|" $file.example > $file || exit 1
  fi
done
chmod +x bin/gazouilleur
echo "...done"
echo
