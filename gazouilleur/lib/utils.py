#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re, urllib, hashlib
from urllib2 import urlopen
from datetime import timedelta
import pymongo, htmlentitydefs
from twisted.internet import defer, reactor
from twisted.internet.threads import deferToThreadPool
from gazouilleur import config
from gazouilleur.lib.log import loggerr

SPACES = ur'[  \s\t\u0020\u00A0\u1680\u180E\u2000-\u200F\u2028-\u202F\u205F\u2060\u3000]'
re_clean_blanks = re.compile(r'%s+' % SPACES)
cleanblanks = lambda x: re_clean_blanks.sub(r' ', x.strip()).strip()

re_shortdate = re.compile(r'^....-(..)-(..)( ..:..).*$')
shortdate = lambda x: re_shortdate.sub(r'\2/\1\3', str(x))

re_parenth = re.compile(r'([\(\)])')
re_leftacc = re.compile(r'(\{)([^\}]*)$')
re_righacc = re.compile(r'^([^\{]*)(\})')
re_leftbrk = re.compile(r'(\[)([^\]]*)$')
re_righbrk = re.compile(r'^([^\[]*)(\])')
def clean_regexp(text):
    return re_leftacc.sub(r'\\\1\2', re_leftbrk.sub(r'\\\1\2', re_righacc.sub(r'\1\\\2', re_righbrk.sub(r'\1\\\2', re_parenth.sub(r'\\\1', text)))))

re_clean_doc = re.compile(r'\.?\s*/[^/]+$')
clean_doc = lambda x: re_clean_doc.sub('.', x).strip()

re_clean_html = re.compile(r'<[^>]*>')
clean_html = lambda x: re_clean_html.sub('', x)

re_clean_identica = re.compile(r'(and posts a ♻ status)? on Identi\.ca( and)?( as a)?', re.I)
clean_identica = lambda x: re_clean_identica.sub('', x)

re_sending_error = re.compile(r'^.* status (\d+) .*details: ({"error":"([^"]*)")?.*$', re.I|re.S)
def sending_error(error):
    error = str(error)
    res = re_sending_error.search(error)
    if res:
        if res.group(3):
            return re_sending_error.sub(r'ERROR \1: \3', error)
        return re_sending_error.sub(r'ERROR \1', error)
    return "ERROR undefined"

re_handle_quotes = re.compile(r'("[^"]*")')
re_handle_simple_quotes = re.compile(r"('[^']*')")
def _handle_quotes(args, regexp):
    for m in regexp.finditer(args):
        args = args.replace(m.group(1), m.group(1)[1:-1].replace(' ', '\s'))
    return args

def handle_quotes(args):
    return _handle_quotes(_handle_quotes(args, re_handle_quotes), re_handle_simple_quotes)

QUOTES = u'«»„‟“”"\'’‘`‛'
def remove_ext_quotes(arg):
    quotes = QUOTES.encode('utf-8')
    return arg.strip().lstrip(quotes).rstrip(quotes).strip()

# URL recognition adapted from Twitter's
# https://github.com/BonsaiDen/twitter-text-python/blob/master/ttp.py
UTF_CHARS = ur'a-z0-9_\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u00ff'
QUOTE_CHARS = r'[%s]' % QUOTES
PRE_CHARS = ur'(?:^|$|%s|%s|[…<>:!()])' % (SPACES, QUOTE_CHARS)
DOMAIN_CHARS = ur'(?:[^\&=\s_\!\.\/]+\.)+[a-z]{2,4}(?::[0-9]+)?'
PATH_CHARS = ur'(?:\([^\)]*\)|[\.,]?[%s!\*\';:=\+\$/%s#\[\]\-_,~@])' % (UTF_CHARS, '%')
QUERY_CHARS = ur'(?:\([^\)]*\)|[a-z0-9!\*\';:&=\+\$/%#\[\]\-_\.,~])'
PATH_ENDING_CHARS = ur'[%s=#/]' % UTF_CHARS
QUERY_ENDING_CHARS = '[a-z0-9_&=#]'
URL_REGEX = re.compile('((%s+)((?:http(s)?://|www\\.)?%s(?:\/%s*%s?)?(?:\?%s*%s)?)(%s))' % (PRE_CHARS, DOMAIN_CHARS, PATH_CHARS, PATH_ENDING_CHARS, QUERY_CHARS, QUERY_ENDING_CHARS, PRE_CHARS), re.I)

ACCENTS_URL = re.compile(r'^\w*[àâéèêëîïôöùûç]', re.I)

def _shorten_url(text):
    for res in URL_REGEX.findall(text):
        if ACCENTS_URL.match(res[2]) or "@" in res[2] and not res[2].startswith('http'):
            continue
        text = text.replace(res[0], '%shttp%s___t_co_xxxxxxxxxx%s' % (res[1], res[3], res[4]))
    return text

re_clean_twitter_command = re.compile(r'^\s*((%s(identica|(twitt|answ)er(only)?)|\d{14}\d*)\s*)+' % config.COMMAND_CHARACTER, re.I)
def countchars(text):
    return len(_shorten_url(_shorten_url(re_clean_twitter_command.sub('', text.strip()).strip())).decode('utf-8'))

re_clean_url1 = re.compile(r'/#!/')
re_clean_url2 = re.compile(r'((\?|&)((utm_(term|medium|source|campaign|content)|xtor)=[^&#]*))', re.I)
re_clean_url3 = re.compile(ur'(%s|%s|[\.…<>:?!=)])+$' % (SPACES, QUOTE_CHARS))
def clean_url(url):
    url = re_clean_url1.sub('/', url)
    for i in re_clean_url2.findall(url):
        if i[1] == "?":
            url = url.replace(i[2], '')
        else:
            url = url.replace(i[0], '')
    url = re_clean_url3.sub('', url)
    return url  

def get_url(url, timeout=8):
    return urlopen(url, timeout=timeout).geturl()

@defer.inlineCallbacks
def _clean_redir_urls(text, urls={}, first=True, pool=None):
    for res in URL_REGEX.findall(text):
        url00 = res[2].encode('utf-8')
        url0 = url00
        if not url00.startswith('http'):
            if "@" in url00 or url00.startswith('#'):
                continue
            url0 = "http://%s" % url00
        if url0 in urls:
            url1 = urls[url0]
            if url1 == url0:
                continue
        else:
            try:
                url1 = yield deferToThreadPool(reactor, pool, get_url, url0, timeout=8)
                url1 = clean_url(url1)
                urls[url0] = url1
                urls[url1] = url1
            except Exception as e:
                if config.DEBUG and not first:
                    loggerr("trying to resolve %s : %s" % (url0, e))
                if "403" in str(e) or "Error 30" in str(e):
                    urls[url0] = url00
                url1 = url00
        if first and not url1 == url00:
            url1 = url1.replace('http', '##HTTP##')
        try:
            url1 = url1.decode('utf-8')
            text = text.replace(res[0], '%s%s%s' % (res[1], url1, res[4]))
        except:
            if config.DEBUG:
                logerr("encoding %s" % url1)
    if not first:
        text = text.replace('##HTTP##', 'http')
    defer.returnValue((text, urls))

@defer.inlineCallbacks
def clean_redir_urls(text, urls, pool=None):
    text, urls = yield _clean_redir_urls(text, urls, pool=pool)
    text, urls = yield _clean_redir_urls(text, urls, False, pool=pool)
    defer.returnValue((text, urls))

def get_hash(url):
    hash = hashlib.md5(url)
    return hash.hexdigest()

re_uniq_rt_hash = re.compile(r'([MLR]T|%s)+\s*@[a-zA-Z0-9_]{1,15}[: ,]*' % QUOTE_CHARS)
re_clean_spec_chars = re.compile(r'(%s|[-_.,;:?!<>(){}[\]/\\~^+=|#@&$%s%s])+' % (QUOTE_CHARS, '%', '…'.decode('utf-8')))
def uniq_rt_hash(text):
    text = re_uniq_rt_hash.sub(' ', text)
    text = re_clean_spec_chars.sub(' ', text)
    text = cleanblanks(text)
    return get_hash(text.encode('utf-8'))

re_entities = re.compile(r'&([^;]+);')
def unescape_html(text):
    return re_entities.sub(lambda x: unichr(int(x.group(1)[1:])) if x.group(1).startswith('#') else unichr(htmlentitydefs.name2codepoint[x.group(1)]), text)

def getTopsyFeedUrl(query):
    return 'http://topsy.com/s/%s/tweet?order=date&window=realtime' % query

def getIcerocketFeedUrl(query, rss=False):
    rss_arg = "&rss=1" if rss else "";
    return 'http://www.icerocket.com/search?tab=twitter&q=%s%s' % (query, rss_arg)

def assembleResults(results, limit=300):
    assemble = []
    line = ""
    for result in results:
        line += " «%s»  | " % str(result.encode('utf-8'))
        if len(line) > limit:
            assemble.append(formatQuery(line, None))
            line = ""
    if line != "":
        assemble.append(formatQuery(line, None))
    return assemble

def formatQuery(query, add_url=None):
    if query:
        query = query[:-4]
    if add_url:
        if add_url.lower() == "icerocket":
            query = getIcerocketFeedUrl(query)
        elif add_url.lower() == "topsy":
            query = getTopsyFeedUrl(query)
    return query

def getFeeds(channel, database, db, url_format=True, add_url=None, randorder=None):
    urls = []
    db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
    queries = list(db["feeds"].find({'database': database, 'channel': channel}, fields=['name', 'query'], sort=[('timestamp', pymongo.ASCENDING)]))
    if database == "tweets":
        # create combined queries on Icerocket/Topsy from search words retrieved in db
        query = ""
        try:
            queries = [queries[i] for i in randorder]
        except:
            pass
        for feed in queries:
            arg = str(feed['query'].encode('utf-8')).replace('@', 'from:')
            rawrg = arg
            space = " OR "
            if url_format:
                if not arg.startswith('from:') and not arg.startswith('#'):
                   arg = "(%s)" % arg
                if add_url:
                    space = "+OR+"
                arg = "%s%s" % (urllib.quote(arg, ''), space)
            else:
                arg = " «%s»  | " % arg
            if " OR " in rawrg or " -" in rawrg:
                urls.append(formatQuery(arg, add_url))
            elif query.count(space) < 3:
                query += arg
            else:
                urls.append(formatQuery(query, add_url))
                query = arg
        if query != "":
            urls.append(formatQuery(query, add_url))
    else:
        if not url_format:
            urls = assembleResults([feed['name'] for feed in queries])
        else:
            urls = [str(feed['query']) for feed in queries]
    return urls

re_arg_page = re.compile(r'&p=(\d+)', re.I)
def next_page(url):
    p = 1
    res = re_arg_page.search(url)
    if res:
        p = int(res.group(1))
        url = re_arg_page.sub('', url)
    p += 1
    return "%s&p=%s" % (url, p)

def save_lasttweet_id(channel, tweet_id):
    db = pymongo.Connection(config.MONGODB['HOST'], config.MONGODB['PORT'])
    db[config.MONGODB['DATABASE']].authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
    db[config.MONGODB['DATABASE']]['lasttweets'].update({'channel': channel}, {'channel': channel, 'tweet_id': tweet_id}, upsert=True)
    db.close()

def safeint(n):
    try:
        return int(n.strip())
    except:
        return 0

def chanconf(chan, conf=None):
    if conf:
        return conf
    if chan:
        chan = chan.lstrip('#').lower()
    try:
        return config.CHANNELS[chan]
    except:
        return None

def get_master_chan(default=config.BOTNAME):
    for chan in config.CHANNELS:
        if "MASTER" in config.CHANNELS[chan]:
            return "#%s" % chan.lower().lstrip('#')
    return default.lower()

def chan_has_protocol(chan, protocol, conf=None):
    protocol = protocol.upper()
    if protocol == "IDENTICA":
        return chan_has_identica(chan, conf)
    elif protocol == "TWITTER":
        return chan_has_twitter(chan, conf)
    return False

def chan_has_identica(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'IDENTICA' in conf and 'USER' in conf['IDENTICA']

def chan_has_twitter(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'KEY' in conf['TWITTER'] and 'SECRET' in conf['TWITTER'] and 'OAUTH_TOKEN' in conf['TWITTER'] and 'OAUTH_SECRET' in conf['TWITTER']

def chan_displays_rt(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'DISPLAY_RT' in conf and conf['DISPLAY_RT']

def chan_displays_my_rt(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'DISPLAY_RT' in conf['TWITTER'] and conf['TWITTER']['DISPLAY_RT']

def chan_allows_twitter_for_all(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'ALLOW_ALL' in conf['TWITTER'] and conf['TWITTER']['ALLOW_ALL']

def is_user_admin(nick):
    return nick in config.ADMINS

def is_user_global(nick):
    return nick in config.GLOBAL_USERS

def is_user_auth(nick, channel, conf=None):
    conf = chanconf(channel, conf)
    return conf and (is_user_global(nick) or is_user_admin(nick) or ('USERS' in conf and nick in conf['USERS']))

def has_user_rights_in_doc(nick, channel, command_doc, conf=None):
    if command_doc is None:
        return is_user_admin(nick)
    if channel == config.BOTNAME.lower():
        channel = get_master_chan()
    conf = chanconf(channel, conf)
    auth = is_user_auth(nick, channel, conf)
    identica = chan_has_identica(channel, conf)
    twitter = chan_has_twitter(channel, conf)
    tw_rights = chan_allows_twitter_for_all(channel, conf) or auth
    if "/IDENTICA" in command_doc:
        if "/TWITTER" in command_doc:
            return identica and twitter and tw_rights
        return identica and tw_rights
    if "/TWITTER" in command_doc:
        return twitter and tw_rights
    if auth:
        return True
    if command_doc.endswith('/AUTH'):
        return False
    return True

timestamp_hour = lambda date : date - timedelta(minutes=date.minute, seconds=date.second, microseconds=date.microsecond)

