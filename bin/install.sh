#!/bin/bash

# Install possible missing packages
echo "Install dependencies..."
echo "-----------------------"
echo
sudo apt-get update > /dev/null || exit 1
sudo apt-get -y install curl git vim python-dev libxml2-dev libfreetype6-dev libpng-dev >> install.log || exit 1
echo

# Install apt repositories for ScrapyD and MongoDB
echo "Add source repositories..."
echo "--------------------------"
echo
curl -s http://docs.mongodb.org/10gen-gpg-key.asc | sudo apt-key add -
sudo cp /etc/apt/sources.list{,.gazouilleurbackup-`date +%Y%m%d-%H%M`}
if ! grep "downloads-distro.mongodb.org" /etc/apt/sources.list > /dev/null; then
cp /etc/apt/sources.list /tmp/sources.list
  echo >> /tmp/sources.list
  echo "# MONGODB repository, automatically added by Gazouilleur's install" >> /tmp/sources.list
  echo "deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen" >> /tmp/sources.list
  sudo mv /tmp/sources.list /etc/apt/sources.list
fi
sudo apt-get update >> install.log || exit 1
echo

# Install MongoDB
echo "Install and start MongoDB..."
echo "----------------------------"
echo
sudo apt-get -y install mongodb-10gen >> install.log || exit 1
sudo pip -q install pymongo >> install.log || exit 1
#possible config via : vi /etc/mongodb.conf
sudo service mongodb restart || exit 1
echo

# Install Gazouilleur's VirtualEnv
echo "Install VirtualEnv..."
echo "---------------------"
echo
sudo pip -q install virtualenv >> install.log || exit 1
sudo pip -q install virtualenvwrapper >> install.log || exit 1
source /usr/local/bin/virtualenvwrapper.sh
mkvirtualenv --no-site-packages gazouilleur
workon gazouilleur
easy_install -U distribute >> install.log || exit 1
pip install -q numpy >> install.log || exit 1
pip install -r requirements.txt >> install.log || exit 1
add2virtualenv .
deactivate
echo

# Copy default config
bash bin/configure.sh

echo "Installation complete!"
echo "----------------------"
echo "Please configure Gazouilleur by editing gazouilleur/config.py"
echo "Then create the Mongo database with appropriate rights by running: bash bin/createDB.sh"
echo "You will then be able to start the bot by running: bash bin/start.sh"
