#!/bin/python
# -*- coding: utf-8 -*-

import sys, os, os.path, time, codecs
sys.path.append('..')
import config

class FileLogger:
    def __init__(self, channel=''):
        filename = config.BOTNAME
        if channel:
            filename += '_' + channel
        filename += '.log'
        if not os.path.isdir('log'):
            os.mkdir('log')
        self.file = codecs.open(os.path.join('log', filename), "a", encoding="utf-8")

    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime(time.time()))
        if not file.closed:
            self.file.write('%s %s\n' % (timestamp, message))
            self.file.flush()

    def close(self):
        self.file.close()
