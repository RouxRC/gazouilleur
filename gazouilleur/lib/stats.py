#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, re, time
from json import dump as write_json
from twisted.internet.defer import inlineCallbacks, returnValue
from datetime import datetime, timedelta
from gazouilleur import config
from gazouilleur.lib.mongo import SingleMongo, find_stats, count_followers, find_last_followers, sortasc, sortdesc
from gazouilleur.lib.log import loggerr
from gazouilleur.lib.utils import *

class Stats(object):

    def __init__(self, user):
        self.user = user
        try:
            self.url = '%s/' % config.URL_STATS.rstrip('/')
        except:
            self.url = None
        self.templates = os.path.join("web", "templates")

    @inlineCallbacks
    def print_last(self):
        now = timestamp_hour(datetime.today())
        since = now - timedelta(days=30)
        stats = yield find_stats({'user': self.user, 'timestamp': {'$gte': since}}, filter=sortdesc('timestamp'))
        if not len(stats):
            returnValue()
        stat = stats[0]
        stat["followers"] = yield count_followers(self.user)
        rts = 0
        fols = 0
        twts = 0
        delays = {1: 'hour', 6: '6 hours', 24: 'day', 7*24: 'week', 30*24: 'month'}
        order = delays.keys()
        order.sort()
        olds = {'tweets': {}, 'followers': {}, 'rts': {}}
        for s in stats:
            d = now - s['timestamp']
            delay = d.seconds / 3600 + d.days * 24
            fols = stat['followers'] - s['followers']
            twts = stat['tweets'] - s['tweets']
            for i in order:
                if delay == i:
                    if 'stats%sH' % i not in olds['tweets']:
                        olds['tweets']['stats%sH' % i] = twts if twts not in olds['tweets'].values() else 0
                    if 'stats%sH' % i not in olds['followers']:
                        olds['followers']['stats%sH' % i] = fols if fols not in olds['followers'].values() else 0
                    if 'stats%sH' % i not in olds['rts']:
                        olds['rts']['stats%sH' % i] = rts if rts not in olds['rts'].values() else 0
            rts += s['rts_last_hour']
        olds['rts']['stats1H'] = stat['rts_last_hour']
        for i in order:
            if rts and 'stats%sH' % i not in olds['rts'] and rts not in olds['rts'].values():
                olds['rts']['stats%sH' % i] = rts
                rts = 0
            if fols and 'stats%sH' % i not in olds['followers']  and fols not in olds['followers'].values():
                olds['followers']['stats%sH' % i] = fols
                fols = 0
            if twts and 'stats%sH' % i not in olds['tweets'] and twts not in olds['tweets'].values():
                olds['tweets']['stats%sH' % i] = twts
                twts = 0
        res = []
        if stat['tweets']:
            res.append("Tweets: %d total" % stat['tweets'] + " ; ".join([""]+["%d last %s" %  (olds['tweets']['stats%sH' % i], delays[i]) for i in order if 'stats%sH' % i in olds['tweets'] and olds['tweets']['stats%sH' % i]]))
        textrts = ["%d last %s" % (olds['rts']['stats%sH' % i], delays[i]) for i in order if 'stats%sH' % i in olds['rts'] and olds['rts']['stats%sH' % i]]
        if textrts:
            res.append("RTs: " + " ; ".join(textrts))
        if stat['followers']:
            res.append("Followers: %d total" % stat['followers'] + " ; ".join([""]+["%+d last %s" % (olds['followers']['stats%sH' % i], delays[i]) for i in order if 'stats%sH' % i in olds['followers'] and olds['followers']['stats%sH' % i]]))
            recent = yield find_last_followers(self.user)
            if recent:
                res.append("Recent follower%s: %s" % ("s include" if len(recent) > 1 else "", format_4_followers(recent)))
        if self.url and res:
            res.append("More details: %sstatic_stats_%s.html" % (self.url, self.user))
        returnValue([(True, "[Stats] %s" % m) for m in res])

    @inlineCallbacks
    def dump_data(self):
        if not self.url:
            returnValue(False)
        stats = yield find_stats({'user': self.user}, filter=sortasc('timestamp'), timeout=120)
        dates = [s['timestamp'] for s in stats]
        tweets = [s['tweets'] for s in stats]
        tweets_diff = [a - b for a, b in zip(tweets[1:],tweets[:-1])]
        followers = [s['followers'] for s in stats]
        followers_diff = [a - b for a, b in zip(followers[1:], followers[:-1])]
        rts_diff = [s['rts_last_hour'] for s in stats]
        rts = []
        n = 0
        for a in rts_diff:
            n += a
            rts.append(n)

        jsondata = {}
        imax = len(dates) - 1
        for i, date in enumerate(dates):
            ts = int(time.mktime(date.timetuple()))
            jsondata[ts] = { 'tweets': tweets[i], 'followers': followers[i], 'rts': rts[i] }
            if i < imax:
                jsondata[ts].update({ 'tweets_diff': tweets_diff[i], 'followers_diff': followers_diff[i], 'rts_diff': rts_diff[i+1] })

        try:
            jsondir = os.path.join('web', 'data')
            if not os.path.exists(jsondir):
                os.makedirs(jsondir)
            with open(os.path.join(jsondir, 'stats_%s.json' % self.user), 'w') as outfile:
                write_json(jsondata, outfile)
        except IOError as e:
            loggerr("Could not write web/data/stats_%s.json : %s" % (self.user, e), action="stats")

        try:
            from plots import CumulativeCurve, DailyHistogram, WeekPunchCard
            imgdir = os.path.join('web', 'img')
            if not os.path.exists(imgdir):
                os.makedirs(imgdir)
            CumulativeCurve(dates, tweets, 'Total tweets', imgdir, 'tweets_%s' % self.user)
            CumulativeCurve(dates, followers, 'Total followers', imgdir, 'followers_%s' % self.user)
            CumulativeCurve(dates, rts, 'Total RTs since %s' % dates[0], imgdir, 'rts_%s' % self.user)
            DailyHistogram(dates[:-1], tweets_diff, 'New tweets', imgdir, 'new_tweets_%s' % self.user)
            DailyHistogram(dates[:-1], followers_diff, 'New followers', imgdir, 'new_followers_%s' % self.user)
            DailyHistogram(dates[:-1], rts_diff[1:], 'New RTs', imgdir, 'new_rts_%s' % self.user)
            WeekPunchCard(dates[:-1], tweets_diff, 'Tweets punchcard', imgdir, 'tweets_card_%s' % self.user)
            WeekPunchCard(dates[:-1], followers_diff, 'Followers punchcard', imgdir, 'followers_card_%s' % self.user)
            WeekPunchCard(dates[:-1], rts_diff[1:], 'RTs punchcard', imgdir, 'rts_card_%s' % self.user)
        except Exception as e:
            loggerr("Could not write images in web/img for %s : %s" % (self.user, e), action="stats")

        data = {'user': self.user, 'url': self.url}
        self.render_template("static_stats.html", self.user, data)
        returnValue(True)

    def render_template(self, template, name, data):
        outfile = template.replace('.html', '_%s.html' % name)
        try:
            import codecs
            import pystache
            from contextlib import nested
            ofile = os.path.join("web", outfile)
            with nested(open(os.path.join(self.templates, template), "r"), codecs.open(ofile, "w", encoding="utf-8")) as (temp, generated):
                generated.write(pystache.Renderer(string_encoding='utf8').render(temp.read(), data))
            os.chmod(ofile, 0o644)
            return True
        except IOError as e:
            loggerr("Could not write web/%s from %s/%s : %s" % (outfile, self.templates, template, e), action="stats")
            return False

    @inlineCallbacks
    def digest(self, hours, channel):
        now = datetime.today()
        since = now - timedelta(hours=hours)
        re_chan = re.compile(r'^#*%s$' % channel.lower(), re.I)
        query = {'channel': re_chan, 'timestamp': {'$gte': since}}
        data = {
            "channel": channel,
            "t0": clean_date(since),
            "t1": clean_date(now),
            "news": [],
            "imgs": [],
            "tweets": []
        }

        news = yield SingleMongo('news', 'find', query, fields=['sourcename', 'source', 'link', 'message'], filter=sortasc('sourcename')+sortasc('timestamp'))
        lastsource = ""
        for n in news:
            source = n["sourcename"]
            if source != lastsource:
                lastsource = source
                data["news"].append({
                    "name": source,
                    "link": n["link"],
                    "elements": []
                })
            data["news"][-1]["elements"].append({
                "text": n["message"],
                "link": n["link"]
            })
        del(news)

        tweets = yield SingleMongo('tweets', 'find', query, fields=['screenname', 'message', 'link'], filter=sortasc('timestamp'))
        links = {}
        imgs = {}
        filters = yield SingleMongo('filters', 'find', {'channel': re_chan}, fields=['keyword'])
        filters = [keyword['keyword'].lower() for keyword in filters]
        for t in tweets:
            skip = False
            tuser_low = t['screenname'].lower()
            if "@%s" % tuser_low in filters:
                continue
            msg_low = t["message"].lower()
            if not ((self.user and self.user in msg_low) or self.user == tuser_low):
                for k in filters:
                    if k in msg_low:
                        skip = True
                        break
            if skip: continue
            for link in URL_REGEX.findall(t["message"]):
                link, _ = clean_url(link[2])
                if not link.startswith("http"):
                    continue
                tid = re_twitmedia.search(link)
                if tid:
                    tid = tid.group(1)
                    if tid not in imgs:
                        imgs[tid] = 1
                        data["imgs"].append({"id": tid})
                    continue
                if re_tweet.match(link):
                    continue
                if link not in links:
                    links[link] = {
                        "link": link,
                        "first": ("%s: %s" % (t["screenname"], t["message"].replace(link, ""))),
                        "firstlink": t["link"],
                        "count": 0
                    }
                links[link]["count"] += 1

        del(tweets)
        data["tweets"] = sorted(links.values(), key=lambda x: "%06d-%s" % (10**6-x['count'], x['link']))
        del(links)

        filename = "%s_%s_%s" % (channel.lstrip("#"), data["t0"].replace(" ", "+"), data["t1"].replace(" ", "+"))
        if not self.render_template("digest.html", filename, data):
            returnValue("Wooops could not generate html for %s..." % filename)
        returnValue("Digest for the last %s hours available at %sdigest_%s.html" % (hours, self.url, filename))

re_tweet = re.compile(r'https?://twitter\.com/\S+/statuse?s?/\d+$')
re_twitmedia = re.compile(r'^https?://twitter\.com/\S+/statuse?s?/(\d+)/(photo|video)/\d+$')
def clean_date(d):
    d = d.isoformat()
    return d[:d.find(":", 15)].replace("T", " ")
