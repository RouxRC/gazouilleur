#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

class ColorConf(object):

    colorcodes = {
      "white": 0,
      "black": 1,
      "blue": 2,
      "green": 3,
      "light red": 4,
      "red": 5,
      "magenta": 6,
      "purple": 6,
      "orange": 7,
      "yellow": 8,
      "light green": 9,
      "cyan": 10,
      "light cyan": 11,
      "light blue": 12,
      "light magenta": 13,
      "light purple": 13,
      "gray": 14,
      "light gray": 15
    }


    default = {             # Default conf
      "colors": {
        "user": "light red",    # answered irc nicknames
        "msgs": "cyan",         # text of irc answers
        "titles": "blue",       # tweets authors and rss names
        "text": "purple",       # tweets messages and rss titles
        "meta": "gray"          # diverse meta information
      },
      "prefix": "  "            # text preceding all messages
    }

    _nocolors = {"all": 1}      # overrides all colors if present in colors

    normal = {              # Classical conf
      "prefix": "",
      "colors": _nocolors
    }

    prefixed = {            # 4 spaces prefix conf
      "prefix": "    ",
      "colors": _nocolors
    }

    def __init__(self, conf="default"):
        if type(conf) is str:
            conf = conf.lower()
            if conf == "default":
                self.conf = dict(self.default)
            elif conf == "normal":
                self.conf = dict(self.normal)
            elif conf == "prefixed":
                self.conf = dict(self.prefixed)
            elif conf in self.colorcodes.keys():
                self.conf = {
                  "prefix": "",
                  "colors": {"all": self.colorcodes[conf]}
                }
            else:
                raise TypeError('Color config\'s name must be one of "default", "normal", "prefixed" or a valid MIRC color name, see list in %s' % __file__)
        elif type(conf) is dict:
            self.conf = dict(self.default)
            self.conf.update(conf)
        else:
            raise TypeError('Colors config must be either a json or a name')
        if type(self.conf["prefix"]) is not str:
            raise TypeError('prefix field must be a string')
        if "all" in self.conf["colors"]:
            for k in ["user", "msgs", "titles", "text", "meta"]:
                self.conf["colors"][k] = self.conf["colors"]["all"]
        self.define_color_patterns()

    def colorcode(self, val):
        if type(val) == int:
            return val
        if type(val) != str:
            raise TypeError('Colors must be either an int or a string')
        try:
            return int(val)
        except:
            pass
        try:
            return self.colorcodes[val.lower()]
        except:
            raise TypeError('Colors as string must be a valid MIRC color name, see list in %s' % __file__)

    def color(self, val):
        code = self.colorcode(val)
        if code < 0 or code > 15:
            raise TypeError('Colors as int must be between 0 and 15')
        if code != 1:
            return "\x03%02d" % code
        return ""

    _re_head = r'PRIVMSG .*?:'
    _re_news = r'\S+(?: \(.*?\))?: |\[[^\]]+\] '
    _re_meta = r'\[[\d\/\s:]+\] '
    re_answ = re.compile(r'^(%s)(\S+: )' % _re_head, re.I)
    re_last = re.compile(r'^(%s)(\S+: )?(%s\S+ — )' % (_re_head, _re_meta), re.I)
    re_lafo = re.compile(r'^(%s)(\S+: )?(%s)(?:\S+ — )(%s)' % (_re_head, _re_meta, _re_news), re.I)
    re_anfo = re.compile(r'^(%s)(\S+: )(%s)' % (_re_head, _re_news), re.I)
    re_foll = re.compile(r'^(%s)(%s)(.* —)' % (_re_head, _re_news), re.I)
    re_extr = re.compile(r'^(%s)(\[[^\]]+\]) ' % _re_head, re.I)
    re_link = re.compile(r'((?:—|\s|https?://\S+)+)( \(.*\))?$', re.I)

    def define_color_patterns(self):
        self._ms = self.color(self.conf["colors"]["msgs"])
        _me = self.color(self.conf["colors"]["meta"])
        _us = self.color(self.conf["colors"]["user"])
        _ti = self.color(self.conf["colors"]["titles"])
        _te = self.color(self.conf["colors"]["text"])
        _gt = lambda x,i: x.group(i) if x.group(i) else ""
        _fo_user = lambda x: _gt(x,1) + _us + _gt(x,2)
        _fo_news = lambda x,i: _ti + _gt(x,i) + _te
        _fo_last = lambda x: _me + _gt(x,3)
        self.fo_answ = lambda x: _fo_user(x) + self._ms
        self.fo_last = lambda x: _fo_user(x) + _fo_last(x) + self._ms
        self.fo_lafo = lambda x: _fo_user(x) + _fo_last(x) + _fo_news(x,4)
        self.fo_anfo = lambda x: _fo_user(x) + _fo_news(x,3)
        self.fo_foll = lambda x: _gt(x,1) + _fo_news(x,2) + _gt(x,3)
        self.fo_extr = lambda x: _gt(x,1) + _ti + _gt(x,2) + self._ms + " "
        self.fo_link = lambda x: _me + _gt(x,1) + _gt(x,2)

    def colorize(self, text):
        if self.re_lafo.search(text):
            text = self.re_lafo.sub(self.fo_lafo, text)
        elif self.re_anfo.search(text):
            text = self.re_anfo.sub(self.fo_anfo, text)
        elif self.re_last.search(text):
            text = self.re_last.sub(self.fo_last, text)
        elif self.re_foll.search(text):
            text = self.re_foll.sub(self.fo_foll, text)
        elif self.re_extr.search(text):
            text = self.re_extr.sub(self.fo_extr, text)
        elif self.re_answ.search(text):
            text = self.re_answ.sub(self.fo_answ, text)
        else:
            text = text.replace(":", ":" + self._ms, 1)
        if self.re_link.search(text):
            text = self.re_link.sub(self.fo_link, text)
        text = text.replace(":", ":%s" % self.conf["prefix"], 1)
        return text

