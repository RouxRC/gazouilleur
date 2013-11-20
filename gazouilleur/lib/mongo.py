#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet.defer import inlineCallbacks, returnValue as returnD
from txmongo import MongoConnection, _MongoFactory
from txmongo.filter import sort as mongosort, ASCENDING, DESCENDING
from gazouilleur.config import DEBUG, MONGODB
from gazouilleur.lib.log import loggerr
if not DEBUG:
    _MongoFactory.noisy = False

@inlineCallbacks
def prepareDB():
    conn = yield MongoConnection(MONGODB['HOST'], MONGODB['PORT'])
    db = conn[MONGODB['DATABASE']]
    db.authenticate(MONGODB['USER'], MONGODB['PSWD'])
    returnD(db)

def closeDB(db):
    try:
        db._Database__factory.doStop()
        return True
    except Exception as e:
        if DEBUG:
            loggerr(e, action="mongodb")
        return False

def sortasc(field):
    return mongosort(ASCENDING(field))

def sortdesc(field):
    return mongosort(DESCENDING(field))

def ensure_indexes(db):
    db['logs'].ensure_index(sortasc('channel') + sortdesc('timestamp'), background=True)
    db['logs'].ensure_index(sortasc('channel') + sortasc('user') + sortdesc('timestamp'), background=True)
    db['tasks'].ensure_index(sortasc('channel') + sortasc('timestamp'), background=True)
    db['feeds'].ensure_index(sortasc('channel') + sortasc('database') + sortdesc('timestamp'), background=True)
    db['filters'].ensure_index(sortasc('channel') + sortasc('keyword') + sortdesc('timestamp'), background=True)
    db['news'].ensure_index(sortasc('channel') + sortdesc('timestamp'), background=True)
    db['news'].ensure_index(sortasc('channel') + sortasc('source') + sortdesc('timestamp'), background=True)
    db['tweets'].ensure_index(sortasc('channel') + sortasc('id') + sortdesc('timestamp'), background=True)
    db['tweets'].ensure_index(sortasc('channel') + sortasc('user') + sortdesc('timestamp'), background=True)
    db['tweets'].ensure_index(sortasc('uniq_rt_hash'), background=True)
    db['lasttweets'].ensure_index(sortasc('channel'), background=True)

