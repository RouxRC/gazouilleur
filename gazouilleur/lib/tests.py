#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys

# Check config.py
try:
    from gazouilleur import config
except ImportError:
    sys.stderr.write("ERROR: Could not find `gazouilleur/config.py`.\nERROR: Please run `bash bin/configure.sh` to create it, then edit it to prepare your bot.\n")
    exit(1)
except SyntaxError as e:
    import traceback
    _, _, exc_traceback = sys.exc_info()
    sys.stderr.write("ERROR: Could not read `gazouilleur/config.py`.\nERROR: Please edit it to fix the following syntax issue:\nERROR: %s\n%s\n" % (e, "\n".join(traceback.format_exc().splitlines()[-3:-1])))
    exit(1)

try:
    config.BOTNAME, config.BOTPASS, config.HOST, config.PORT, config.MONGODB, config.GLOBAL_USERS, config.TWITTER_API_VERSION, config.TWITTER_API_LIMIT, config.BACK_HOURS, config.COMMAND_CHARACTER, config.CHANNELS, config.DEBUG, config.ADMINS
    [config.MONGODB[k] for k in ['HOST', 'PORT', 'DATABASE', 'USER', 'PSWD']]
except AttributeError as e:
    sys.stderr.write("ERROR: Some field is missing from `gazouilleur/config.py`.\nERROR: Please edit it to fix the following issue:\nERROR: %s\n" % str(e).replace("'module' object", 'config'))
    exit(1)
except KeyError as e:
    sys.stderr.write("ERROR: A field is missing from MONGODB config in `gazouilleur/config.py`: %s.\n" % e)
    exit(1)
try:
    assert(len([1 for c in config.CHANNELS.values() if "MASTER" in c and c["MASTER"]]) == 1)
    [c[k] for k in ['USERS', 'DISPLAY_RT'] for c in config.CHANNELS.values()]
except AssertionError:
    sys.stderr.write("ERROR: One and only one channel must be set as MASTER in `gazouilleur/config.py`.\nERROR: Please edit it to fix this issue.\n")
    exit(1)
except KeyError as e:
    sys.stderr.write("ERROR: A field is missing from one channel set in `gazouilleur/config.py`: %s.\n" % e)
    exit(1)
try:
    [c['IDENTICA']['USER'] for c in config.CHANNELS.values() if "IDENTICA" in c]
except KeyError:
    sys.stderr.write("ERROR: USER field is missing from IDENTICA config in `gazouilleur/config.py`.\n")
    exit(1)
try:
    [c['TWITTER'][k] for k in ['USER', 'DISPLAY_RT', 'KEY', 'SECRET', 'OAUTH_TOKEN', 'OAUTH_SECRET'] for c in config.CHANNELS.values() if "TWITTER" in c]
except KeyError as e:
    sys.stderr.write("ERROR: A field is missing from TWITTER config in `gazouilleur/config.py`: %s.\n" % e)
    exit(1)

# Check dependencies
try:
    import pymongo, lxml, twisted, twitter, feedparser, pypump
except ImportError as e:
    sys.stderr.write("ERROR: Could not load module%s.\nERROR: Please check your install or run `pip install -r requirements.txt` from gazouilleur's virtualenv.\n" % str(e).replace('No module named', ''))
    exit(1)

# Check plotting dependencies if webstats activated
if config.URL_STATS:
    try:
        import pystache, pylab, matplotlib
    except ImportError as e:
        sys.stderr.write("ERROR: Could not load module%s.\nERROR: This module is required to activate the Twitter web stats set in URL_STATS in `gazouilleur/config.py`: %s\nERROR: Please check your installl or run `pip install -r requirements.txt` from gazouilleur's virtualenv.\n" % (str(e).replace('No module named', ''), config.URL_STATS))
        exit(1)

# Check MongoDB
try:
    db = pymongo.Connection(config.MONGODB['HOST'], config.MONGODB['PORT'])[config.MONGODB['DATABASE']]
    assert(db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD']))
except pymongo.errors.AutoReconnect as e:
    sys.stderr.write("ERROR: MongoDB is unreachable, %s \nERROR: Please check `mongo` is installed and restart it with `sudo /etc/init.d/mongodb restart`\nERROR: You may need to repair your database, run `tail -n 30 /var/log/mongodb/mongodb.log` for more details.\nERROR: Classic cleaning would be: `sudo /etc/init.d/mongodb stop; sudo rm /var/lib/mongodb/mongod.lock; sudo -u mongodb mongod --dbpath /var/lib/mongodb --repair --repairpath /var/lib/mongodb/%s\n" % (e, config.BOTNAME))
    exit(1)
except AssertionError:
    sys.stderr.write("ERROR: Cannot connect to database %s in MongoDB.\nERROR: Please check the database and its users are created,\nERROR: or run `bash bin/configureDB.sh` to create or update them automatically.\n" % config.MONGODB['DATABASE'])
    exit(1)

# Check Identi.ca config
if [1 for c in config.CHANNELS.values() if "IDENTICA" in c]:
    try:
        from gazouilleur.identica_auth_config import identica_auth
    except ImportError:
        sys.stderr.write("ERROR: Could not find `gazouilleur/identica_auth_config.py`.\nERROR: Please run `python bin/auth_identica.py` to generate your OAuth Identi.ca keys and create it automatically.\n")
        exit(1)
from gazouilleur.lib.microblog import Microblog
for chan, conf in config.CHANNELS.iteritems():
    if "IDENTICA" not in conf:
        continue
    conn = Microblog("identica", conf)
    if not conn.ping():
        sys.stderr.write("ERROR: Cannot connect to Identi.ca with the auth configuration provided in `gazouilleur/identica_auth_config.py` for channel %s and user @%s.\nERROR: Please \n" % (chan, conf["IDENTICA"]["USER"].lower()))
        exit(1)

# Check Twitter config
for chan, conf in config.CHANNELS.iteritems():
    if "TWITTER" not in conf:
        continue
    conn = Microblog("twitter", conf)
    if not conn.ping():
        sys.stderr.write("ERROR: Cannot connect to Twitter with the auth configuration provided in `gazouilleur/config.py` for channel %s and user @%s.\nERROR: Please check you properly set the 4 auth fields and gave \"Read, write, and direct messages\" rights to gazouilleur's app on https://dev.twitter.com\n" % (chan, conf["TWITTER"]["USER"]))
        exit(1)

# Check IRC server
from twisted.internet import reactor, protocol
from twisted.words.protocols.irc import IRCClient

class IRCBotTest(IRCClient):
    def connectionMade(self):
        self.factory.doStop()
class IRCBotTester(protocol.ClientFactory):
    protocol = IRCBotTest
    def clientConnectionFailed(self, connector, reason):
        sys.stderr.write("ERROR: Cannot connect to IRC server %s on port %d: %s.\nERROR: Please check your configuration in `gazouilleur/config.py`.\n" % (config.HOST, config.PORT, reason.getErrorMessage()))
        self.doStop()
        reactor.stop()

d = reactor.connectTCP(config.HOST, config.PORT, IRCBotTester())
