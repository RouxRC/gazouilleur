#!/usr/bin/env python
# -*- coding: utf-8 -*-

import inspect, time
from twisted.internet.defer import inlineCallbacks, returnValue as returnD
from twisted.internet.task import LoopingCall
from txmongo import MongoConnection, _MongoFactory, collection
from txmongo.filter import sort as mongosort, ASCENDING, DESCENDING
from gazouilleur.config import DEBUG, MONGODB
from gazouilleur.lib.log import loggerr
_MongoFactory.noisy = False

class MongoConn(object):

    def __init__(self, retries=3, timeout=0):
        self.retries = retries
        self.timeout = max(30, timeout)
        self.supervisor = LoopingCall(self.__check_timeout__)
        self.conn = None
        self.db = None
        self.coll = None
        self.method = None
        # inject all methods defined in the MongoCollection class
        for m in inspect.getmembers(collection.Collection, predicate=inspect.ismethod):
            setattr(self, m[0], self.__get_proxy__(m[0]))

    @inlineCallbacks
    def close(self):
        if self.supervisor.running:
            self.supervisor.stop()
        if self.conn:
            try:
                yield self.conn.disconnect()
            except Exception as e:
                pass
            del self.conn
            self.conn = None
        self.db = None
        self.coll = None
        self.method = None

    def logerr(self, action, message=""):
        if self.coll:
            action += " %s" % self.coll
        if self.method:
            action += " %s" % self.method
        loggerr("%s. %s" % (action, message), action="mongodb")

    def __get_proxy__(self, method):
        @inlineCallbacks
        def __proxy(coll, *args, **kwargs):
            self.timedout = time.time() + self.timeout
            self.supervisor.start(self.timeout)
            res = yield self.__run__(coll, method, *args, **kwargs)
            if time.time() > self.timedout:
                self.logerr("YEAH REACHED %s AFTER TIMEOUT %s!!! %s %s" % (time.time() - self.timedout, self.timeout, self.coll, self.method))

            if self.supervisor.running:
                self.supervisor.stop()
            returnD(res)
        return __proxy

    def __check_timeout__(self):
        due = time.time() - self.timedout
        if due > 0:
            self.logerr("MONGO TIMEOUT (%s)!!! %s %s since %s" % (self.timeout, self.coll, self.method, due))
            if due > self.timeout:
                self.logerr("MONGO DOUBLE TIMEOUT (%s) closing now %s %s" % (int(due + self.timeout), self.coll, self.method))
                self.close()
                #raise Exception(msg)
            #self.supervisor.stop()

    @inlineCallbacks
    def __run__(self, coll, method, *args, **kwargs):
        attempts_left = self.retries
        result = []
        lasttry = False
        if 'lasttry' in kwargs:
            lasttry = True
            del kwargs['lasttry']
        while True:
            try:
                self.coll = coll
                self.method = method
                if not self.conn and not self.db:
                    status = "Connec"
                    self.conn = yield MongoConnection(MONGODB['HOST'], MONGODB['PORT'], reconnect=False)
                    self.db = self.conn[MONGODB['DATABASE']]
                    status = "Authentica"
                    yield self.db.authenticate(MONGODB['USER'], MONGODB['PSWD'])
                status = "Communica"
                result = yield getattr(self.db[coll], method)(*args, **kwargs)
            except Exception as e:
                if not lasttry:
                    if attempts_left > 0:
                        attempts_left -= 1
                        #if DEBUG:
                        self.logerr("%sting" % status, "Retry #%d" % (self.retries-attempts_left))
                        try:
                            yield self.conn.disconnect()
                        except:
                            pass
                        continue
                    #if DEBUG:
                    self.logerr("%sting" % status, "HARD RETRY %s %s" % (type(e), str(e)))
                    result = yield Mongo(coll, method, *args, lasttry=True, timeout=self.timeout, **kwargs)
                yield self.close()
            if self.supervisor.running:
                self.supervisor.stop()
            returnD(result)

@inlineCallbacks
def Mongo(coll, method, *args, **kwargs):
    timeout = kwargs.pop('timeout', 30)
    db = MongoConn(timeout=timeout)
    res = yield getattr(db, method)(coll, *args, **kwargs)
    yield db.close()
    del db
    returnD(res)

def sortasc(field):
    return mongosort(ASCENDING(field))

def sortdesc(field):
    return mongosort(DESCENDING(field))

@inlineCallbacks
def save_lasttweet_id(channel, tweet_id):
    yield Mongo('lasttweets', 'update', {'channel': channel}, {'channel': channel, 'tweet_id': tweet_id}, upsert=True)

@inlineCallbacks
def find_stats(query, **kwargs):
    res = yield Mongo('stats', 'find', query, **kwargs)
    returnD(res)

@inlineCallbacks
def ensure_indexes():
    db = MongoConn()
    yield db.ensure_index('logs', sortasc('channel') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('logs', sortasc('channel') + sortasc('user') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('tasks', sortasc('channel') + sortasc('timestamp'), background=True)
    yield db.ensure_index('feeds', sortasc('database') + sortasc('timestamp'), background=True)
    yield db.ensure_index('feeds', sortasc('channel') + sortasc('database') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('filters', sortasc('channel') + sortasc('keyword') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('news', sortasc('channel') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('news', sortasc('channel') + sortasc('source') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('tweets', sortasc('channel') + sortasc('id') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('tweets', sortasc('channel') + sortasc('user') + sortdesc('timestamp'), background=True)
    yield db.ensure_index('tweets', sortasc('channel') + sortdesc('id'), background=True)
    yield db.ensure_index('tweets', sortdesc('id') + sortasc('channel') + sortasc('uniq_rt_hash'), background=True)
    yield db.ensure_index('stats', sortdesc('timestamp') + sortasc('user'), background=True)
    yield db.ensure_index('lasttweets', sortasc('channel'), background=True)
    yield db.close()
    del db

