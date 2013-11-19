#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import defer
from txmongo import MongoConnection, _MongoFactory
from txmongo.filter import sort as mongosort, ASCENDING, DESCENDING
from gazouilleur.config import DEBUG, MONGODB
from gazouilleur.lib.log import loggerr
if not DEBUG:
    _MongoFactory.noisy = False

@defer.inlineCallbacks
def prepareDB():
    conn = yield MongoConnection(MONGODB['HOST'], MONGODB['PORT'])
    db = conn[MONGODB['DATABASE']]
    yield db.authenticate(MONGODB['USER'], MONGODB['PSWD'])
    defer.returnValue(db)

@defer.inlineCallbacks
def closeDB(db):
    try:
        yield db._Database__factory.doStop()
        defer.returnValue(True)
    except Exception as e:
        if DEBUG:
            loggerr(e, "mongodb", error=True)
        defer.returnValue(False)

def sortasc(field):
    return mongosort(ASCENDING(field))

def sortdesc(field):
    return mongosort(DESCENDING(field))

