# Gazouilleur

Gazouilleur is an IRC bot offering Twitter interactions on multiple channels in order to:

 * display one channel's Twitter account's tweets, direct messages, mentions and optionally retweets
 * measure and visualise its statistics
 * send on Twitter messages, answers, retweets or direct messages and duplicates on Identi.ca
 * remove messages from Twitter
 * follow or unfollow on demand the results of any search query on Twitter (through Twitter's search & streaming APIs or via the parsing of IceRocket.com, or alternatively Topsy.com, HTML search results.)

Inspired by [La Quadrature du Net](http://www.laquadrature.net/)'s IRC bot [UnGarage](https://www.laquadrature.net/fr/chat-old) developped by [Bram](http://blog.worlddomination.be/projects/ungarage.html), Gazouilleur was developped for the daily organisational and collaborative needs of [Regards Citoyens](http://www.regardscitoyens.org/).

### More functionalities include:

 * display news links from on demand followed rss feeds
 * count the length of a message to be sent on Twitter
 * log tweets in an easily exportable MongoDB
 * ping lists of users of a channel
 * retrieve on demand previous messages on a channel
 * log to files conversations in channels
 * filter on demand messages to be displayed by the bot
 * program future desired tasks
 * shut up on request
 * display debug messages to admin users
 * optional fine control over user rights and channel commands
 * ...

See the list of all available IRC commands in [LIST_COMMANDS.md](/LIST_COMMANDS.md)



## Easy Install (Debian/Ubuntu)

First download the repository:

 ```bash
 git clone https://github.com/RouxRC/gazouilleur.git
 cd gazouilleur
 ```

For an easy install on Debian and CentOS like distributions, you can try running `bash bin/install.sh` or follow step by step the [installation script readable here](/bin/install.sh).

After dependencies are installed, you will need to edit your configuration in `gazouilleur/config.py`, then run `bash bin/configureDB.sh` to prepare your Mongo database.

Depending on the desired options, the configuration will require to get Twitter and/or Identi.ca API rights ([see below](#getting-twitter--identica-api-rights-for-a-channel)).

You can also scroll down to the detailed [installation instructions below](#detailed-installation-instructions).

## Run Gazouilleur

 * Start, stop or restart the bot:
Just run the starter script with either argument start, stop or restart.
Add --nologs option do disable log display after start.

 ```bash
 bin/gazouilleur <start|stop|restart> [--nologs]
 ```

 * Follow logs:

 ```bash
 tail -fn 50 log/run.log
 ```

 * Autostart bot on machine reboot via crontab:
Add the following line via `crontab -e` where $GAZOUILLEUR_PATH is Gazouilleur's install path:

 ```bash
 @reboot     $GAZOUILLEUR_PATH/bin/gazouilleur start --quiet
 ```

## Getting Twitter & Identi.ca API rights for a channel

### Why create a Twitter API application?

In order to send tweets from IRC, each channel needs to be associated with a distinct Twitter account and its API tokens with "Read, Write, and Direct Messages" rights.

"Read only" rights can be sufficient if and only if "FORBID_POST" option is set for the channel : this case allows one to use Twitter's streaming and search API for monitoring keywords or accounts without wanting to send tweets.

Such monitoring is also permitted, with less accuracy, for configs without any Twitter account, by parsing IceRocket.com or Topy.com's HTML search results, but the accuracy and completeness is seriously impacted.

### How to create a Twitter API application?

  + Logon to [https://dev.twitter.com/apps/new](https://dev.twitter.com/apps/new) with a regular Twitter account
  + Fill the required fields on the creation page (name, description and website really do not matter much) and validate
  + Select the "Settings" tab and set the "Access" field in the "Application Type" section considering the [conditions described above](#getting-twitter--identica-api-rights-for-a-channel), then validate
  + Select back the "Details" tab and click "Create my access token"
  + Select the "OAuth Tool" tab to get your 4 API keys in order (KEY, SECRET, OAUTH_TOKEN, OAUTH_SECRET)


### Getting Identi.ca API rights for a channel

 * [Create](https://identi.ca/main/register) or [recover](https://identi.ca/main/recover) an Identi.ca account on the new Pump.io service.

 * Set your Identi.ca USER name in `gazouilleur/config.py`

 * Run the following commands and be guided:

 ```bash
 source /usr/local/bin/virtualenvwrapper.sh
 workon gazouilleur
 python bin/auth_identica.py
 deactivate
 ```

## Detailed Installation Instructions

(These instuctions are meant for GNU/Linux Debian/Ubuntu-like and CentOS-like distributions. Experiences on other distribs welcome!)

### Requirements

 * The following Debian-like packages, quite common, are necessary:

 ```bash
 sudo apt-get install curl git vim python-dev libxml2-dev libfreetype6-dev libpng-dev libxslt1-dev libffi-dev
 ```

 * On CentOS:

 ```bash
 sudo yum install curl git vim python-devel python-setuptools python-pip easy_install libxml2 libxml2-dev libfreetype6-dev libpng-dev libxslt libxslt-devel gcc libffi-devel openssl-devel
 sudo easy_install pip
 ```

### Download the code

 ```bash
 git clone https://github.com/RouxRC/gazouilleur.git
 cd gazouilleur
 ```
 
### Dependencies: [MongoDB](http://www.mongodb.org/)

**Note:** MongoDB being limited to 2Go databases on 32bit systems, it is recommanded to install Gazouilleur on a 64bit machine for extreme use of the Twitter keyword tracking functionnality.

**Note2:** MongoDB Version 2.2 at least is required to get the aggregate functions to work properly. Everything will work with older versions except for the "!tweetswith" command.

 * On Debian/Ubuntu:

Edit your apt `sources.list` file to include the following line:

```bash
deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen
```

Install the GPG key for this repository, update apt lists and install MongoDB:

```bash
curl -s http://docs.mongodb.org/10gen-gpg-key.asc | sudo apt-key add -
sudo apt-get update
sudo apt-get install mongodb-10gen
sudo service mongodb restart
```

You can configure the MongoDB server by editing `/etc/mongodb.conf`.

 * On CentOS, this is slightly more complex:

```bash
    echo "[mongodb]
name=MongoDB Repository
baseurl=http://downloads-distro.mongodb.org/repo/redhat/os/x86_64/
gpgcheck=0
enabled=1" > mongodb.repo.tmp
    sudo mv mongodb.repo.tmp /etc/yum.repos.d/mongodb.repo
    # Then update yum's source list and install:
    sudo yum check-update
    sudo yum install mongo-10gen mongo-10gen-server
    sudo chkconfig mongod on
    sudo service mongod restart
```

**Admin use:** [RockMongo](http://rockmongo.com/) is a nice PhpMyAdmin-like web tool to examine a MongoDB.


### Prepare the Python environment

 * It's recommended to use `virtualenv` with `virtualenvwrapper`:

  ```bash
  sudo pip install virtualenv
  sudo pip install virtualenvwrapper
  ```

 * Create a virtualenv for the bot from within this directory and install dependencies:

  ```bash
  source $(which virtualenvwrapper.sh)
  mkvirtualenv --no-site-packages gazouilleur
  workon gazouilleur
  easy_install -U distribute
  # Install NumPy if you want to activate the URL_STATS option
  # pip install -q numpy
  # Uncomment first NumPy related lines in requirements.txt to activate URL_STATS
  pip install -r requirements.txt
  add2virtualenv .
  deactivate
  ```

### Configuration

 * Prepare your configuration by generating template files by running:

 ```bash
 bash bin/configure.sh
 ```

 * Get your Twitter and Identi.ca API keys if needed [as explained above](#getting-twitter--identica-api-rights-for-a-channel).


 * Choose a name for the bot and preferably register it on the desired IRC server. For instance on Freenode, do from an IRC client:

 ```bash
 /nick <BOTNAME>
 /msg NickServ REGISTER <BOTPASS> <EMAIL>
 /msg NickServ VERIFY REGISTER <BOTNAME> <KEY_RECEIVED_ON_EMAIL>
 ```

 * Set BOTNAME and BOTPASS in `gazouilleur/config.py` and complete the different parts of the global configuration and the specific channels settings.


 * Create the MongoDB database and its owner both having the same name as the bot by running:

 ```bash
 bash bin/configureDB.sh
 ```

 * Run Gazouilleur!

 ```bash
 bin/gazouilleur start
 ```

## How to update to the latests code modifications?

Run the following script:

 ```bash
 bin/update.sh
 ```

Then check your configuration file against `gazouilleur/config.py.example` to add any new possible option.

To use an Identi.ca account since the Pump.io migration, the following commands must also be ran after setting IDENTICA's USER in `gazouilleur/config.py`:

 ```bash
 source /usr/local/bin/virtualenvwrapper.sh
 workon gazouilleur
 python bin/auth_identica.py
 deactivate
 ```


### [Come over see the bot in action and ask any question on Regards Citoyens's IRC channel on Freenode! (irc://irc.freenode.net:#RegardsCitoyens)](https://kiwiirc.com/client/irc.freenode.net/?nick=gazou|?#regardscitoyens)
