#!/bin/python
# -*- coding: utf-8 -*-

import sys, os, os.path, time
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
        self.file = open(os.path.join('log', filename), "a")

    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime(time.time()))
        self.file.write('%s %s\n' % (timestamp, message))
        self.file.flush()

    def close(self):
        self.file.close()
