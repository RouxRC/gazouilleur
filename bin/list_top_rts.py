#!/usr/bin/env python
# -*- coding: utf-8 -*-

from gazouilleur import config
from pymongo import MongoClient
from pprint import pprint
db = MongoClient(config.MONGODB['HOST'], config.MONGODB['PORT'])[config.MONGODB['DATABASE']]

for chan in config.CHANNELS:
    if "TWITTER" not in config.CHANNELS[chan]:
        continue
    account = config.CHANNELS[chan]["TWITTER"]["USER"]
    tweets = []
    for tweet in db["tweets"].find({"channel": "#%s" % chan.lower(), "user": account.lower()}, fields=["uniq_rt_hash", "message"]):
        if tweet["message"].startswith("RT @"):
            continue
        tweets.append({"text": tweet["message"], "rts": db["tweets"].find({"channel": "#%s" % chan.lower(), "uniq_rt_hash": tweet["uniq_rt_hash"]}).count()})
    top = sorted(tweets, key=lambda k: -k['rts'])[:10]
    print "------------"
    print "TOP 10 RTS for @%s" % account
    print "------------"
    pprint(top)
    print ""
