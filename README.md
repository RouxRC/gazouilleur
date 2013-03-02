# Gazouilleur

Gazouilleur is an IRC bot offering Twitter interactions on multiple channels in order to:

 * display one channel's Twitter account's tweets, direct messages, mentions and optionally retweets
 * measure and visualise its statistics
 * send on both Twitter and Identi.ca messages, answers, retweets or direct messages
 * remove messages from Twitter
 * follow or unfollow on demand the results of any search query on Twitter (through IceRocket.com's RSS feeds)

Inspired by [La Quadrature du Net](http://www.laquadrature.net/)'s IRC bot [UnGarage](https://www.laquadrature.net/fr/chat-old) developped by [Bram](http://blog.worlddomination.be/projects/ungarage.html), Gazouilleur was developped for the daily organisational and collaborative needs of [Regards Citoyens](http://www.regardscitoyens.org/).

### More functionalities include:

 * display news links from on demand followed rss feeds
 * count the length of a message to be sent on Twitter
 * log tweets in an easily exportable MongoDB
 * retrieve on demand previous messages on a channel
 * log to files conversations in channels
 * filter on demand messages to be displayed by the bot
 * program future desired tasks
 * shut up on request
 * display debug messages to admin users
 * optional fine user control


## Requirements

 * [MongoDB](http://www.mongodb.org/) is required: below is an example to install it on Debian/Ubuntu:
  + Edit your apt `sources.list` file and add the following line:

  ```bash
  deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen
  ```

  + Install the GPG key for this repository, update apt lists and install MongoDB:

  ```bash
  curl -s http://docs.mongodb.org/10gen-gpg-key.asc | sudo apt-key add -
  sudo apt-get update
  sudo apt-get install mongodb-10gen
  ```

  + Configure MongoDB:

  ```bash
  sudo vi /etc/mongodb.conf
  ```

 * Configure your python environment:
  + It's recommended to use virtualenv with virtualenvwrapper:

  ```bash
  sudo pip install virtualenv
  sudo pip install virtualenvwrapper
  ```

  + Create a virtualenv for the bot from within this directory and install dependencies:

  ```bash
  source /usr/local/bin/virtualenvwrapper.shworkon VIRTUALENV_NAME
  pip install -r requirements.txt
  add2virtualenv .
  ```

## Configuration

 * Adapt the paths and virtualenv's name in `bin/start.sh`
 * Choose a name for the bot and register it on the desired IRC server
 * Create a MongoDB database and its owner both having the same name as the bot ([RockMongo](http://rockmongo.com/) is a nice web tool to do things like this)
 * Copy the configuration example file and adapt your settings:

 ```bash
 cp gazouilleur/config.py{.example,}
 vi gazouilleur/config.py
 ```

## Run Gazouilleur

 * Start or stop the bot:

 ```bash
 bash bin/start.sh &
 bash bin/stop.sh
 ```

 * Follow logs:

 ```bash
 tail -fn 50 run.log
 ```

### [Come over and see the bot in action on Regards Citoyens's IRC channel on Freenode!](http://webchat.freenode.net/?channels=regardscitoyens)

