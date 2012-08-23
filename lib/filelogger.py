#!/bin/python
# -*- coding: utf-8 -*-

import sys, os, os.path, codecs
from datetime import datetime
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
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not self.file.closed:
            self.file.write('%s %s\n' % (timestamp, message))
            self.file.flush()

    def close(self):
        self.file.close()
