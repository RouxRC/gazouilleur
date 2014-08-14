#!/bin/bash

# Install possible missing packages
echo "Install dependencies..."
echo "-----------------------"
echo
if apt-get > /dev/null 2>&1; then
  sudo apt-get update > /dev/null || exit 1
  sudo apt-get -y install curl git vim python-dev libxml2-dev libfreetype6-dev libpng-dev libxslt1-dev libffi-dev >> install.log || exit 1
else
  sudo yum check-update > /dev/null 2>&1 || exit 1
  sudo yum -y install curl git vim python-devel python-setuptools python-pip easy_install libxml2 libxml2-dev libfreetype6-dev libpng-dev libxslt libxslt-devel gcc libffi-devel openssl-devel >> install.log || exit 1
  sudo easy_install pip >> install.log || exit 1
fi
echo

# Install apt repository for MongoDB
echo "Add Mongo source repository..."
echo "------------------------------"
echo
if apt-get > /dev/null 2>&1; then
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
else
  if ! test -s /etc/yum.repos.d/mongodb.repo; then
    echo "[mongodb]
name=MongoDB Repository
baseurl=http://downloads-distro.mongodb.org/repo/redhat/os/x86_64/
gpgcheck=0
enabled=1" > mongodb.repo.tmp
    sudo mv mongodb.repo.tmp /etc/yum.repos.d/mongodb.repo
  fi
  sudo yum check-update >> install.log || exit 1
fi
echo

# Install MongoDB
echo "Install and start MongoDB..."
echo "----------------------------"
echo "possible config via : vi /etc/mongodb.conf"
echo
if apt-get > /dev/null 2>&1; then
  sudo apt-get -y install mongodb-10gen >> install.log || exit 1
  sudo service mongodb restart || exit 1
else
  sudo yum -y install mongo-10gen mongo-10gen-server >> install.log || exit 1
  sudo chkconfig mongod on >> install.log || exit 1
  sudo service mongod restart || exit 1
fi
echo

# Install Gazouilleur's VirtualEnv
echo "Install VirtualEnv..."
echo "---------------------"
echo
sudo pip -q install virtualenv >> install.log || exit 1
sudo pip -q install virtualenvwrapper >> install.log || exit 1
source $(which virtualenvwrapper.sh)
mkvirtualenv --no-site-packages gazouilleur
workon gazouilleur
easy_install -U distribute >> install.log || exit 1
# NumPy only necessary if STATS_URL set in gazouilleur/config.py
#pip install -q numpy >> install.log || exit 1
pip install -r requirements.txt >> install.log || exit 1
add2virtualenv .
deactivate
echo

# Copy default config
bash bin/configure.sh

echo "Installation complete!"
echo "----------------------"
echo "Please configure Gazouilleur by editing gazouilleur/config.py (you may need to create Twitter/Identi.ca API accounts, see README.md for more details."
echo "Then create the Mongo database with appropriate rights by running: \`bash bin/configureDB.sh\`"
echo "You will then be able to start the bot by running: bin/gazouilleur start"
