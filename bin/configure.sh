#!/bin/bash

echo "Configure..."
echo "------------"
for file in gazouilleur/config.py bin/gazouilleur; do
  if ! test -f "$file" || [ "$file" == "bin/gazouilleur" ]; then
    echo " preparing $file from example"
    sed "s|##GAZOUILLEURPATH##|"`pwd`"|" $file.example > $file || exit 1
  fi
done
chmod +x bin/gazouilleur
echo "...done"
echo
