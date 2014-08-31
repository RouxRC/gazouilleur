#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from twisted.internet.defer import inlineCallbacks, returnValue as returnD
from txmongo import MongoConnection, connection
from txmongo.filter import sort as mongosort, ASCENDING, DESCENDING
from gazouilleur.config import DEBUG, MONGODB
connection._Connection.noisy = False


db_foll_coll = lambda x: "followers.%s" % x.lower().lstrip("@")


def sortasc(field):
    return mongosort(ASCENDING(field))

def sortdesc(field):
    return mongosort(DESCENDING(field))


@inlineCallbacks
def SingleMongo(coll, method, *args, **kwargs):
    conn = MongoConnection(MONGODB['HOST'], MONGODB['PORT'])
    db = conn[MONGODB['DATABASE']]
    yield db.authenticate(MONGODB['USER'], MONGODB['PSWD'])
    res = yield getattr(db[coll], method)(*args, **kwargs)
    conn.disconnect()
    returnD(res)

@inlineCallbacks
def save_lasttweet_id(channel, tweet_id):
    yield SingleMongo('lasttweets', 'update', {'channel': channel}, {'channel': channel, 'tweet_id': tweet_id}, upsert=True)

@inlineCallbacks
def find_stats(query, **kwargs):
    res = yield SingleMongo('stats', 'find', query, **kwargs)
    returnD(res)

@inlineCallbacks
def count_followers(user):
    res = yield SingleMongo(db_foll_coll(user), 'find', {"follows_me": True})
    returnD(len(res))

@inlineCallbacks
def find_last_followers(user):
    res = yield SingleMongo(db_foll_coll(user), 'find', {"screen_name": {"$exists": True}, "follows_me": True, "last_update": {"$gte": time.time() - 12*3600}})
    returnD(res)


@inlineCallbacks
def ensure_indexes(db):
    yield db['logs'].ensure_index(sortasc('channel') + sortdesc('timestamp'), background=True)
    yield db['logs'].ensure_index(sortasc('channel') + sortasc('user') + sortdesc('timestamp'), background=True)
    yield db['tasks'].ensure_index(sortasc('channel') + sortasc('timestamp'), background=True)
    yield db['feeds'].ensure_index(sortasc('database') + sortasc('timestamp'), background=True)
    yield db['feeds'].ensure_index(sortasc('channel') + sortasc('database'), background=True)
    yield db['feeds'].ensure_index(sortasc('channel') + sortasc('database') + sortdesc('timestamp'), background=True)
    yield db['filters'].ensure_index(sortasc('channel'), background=True)
    yield db['filters'].ensure_index(sortasc('channel') + sortasc('keyword') + sortdesc('timestamp'), background=True)
    yield db['news'].ensure_index(sortdesc('_id') + sortasc('channel'), background=True)
    yield db['news'].ensure_index(sortasc('channel') + sortdesc('timestamp'), background=True)
    yield db['news'].ensure_index(sortasc('channel') + sortasc('source') + sortdesc('timestamp'), background=True)
    yield db['dms'].ensure_index(sortasc('id') + sortasc('channel'), background=True)
    yield db['tweets'].ensure_index(sortasc('id'), background=True)
    yield db['tweets'].ensure_index(sortasc('channel') + sortdesc('id'), background=True)
    yield db['tweets'].ensure_index(sortasc('channel') + sortasc('id') + sortdesc('timestamp'), background=True)
    yield db['tweets'].ensure_index(sortasc('channel') + sortasc('user') + sortdesc('timestamp'), background=True)
    yield db['tweets'].ensure_index(sortdesc('id') + sortasc('channel') + sortasc('uniq_rt_hash'), background=True)
    yield db['stats'].ensure_index(sortdesc('timestamp') + sortasc('user'), background=True)
    yield db['lasttweets'].ensure_index(sortasc('channel'), background=True)

