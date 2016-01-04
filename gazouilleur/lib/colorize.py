#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Colorize function stolen and adapted from @Yomguithereal's colifrapy
# https://github.com/Yomguithereal/colifrapy/blob/master/colifrapy/tools/colorize.py

import sys

# Possible Colors and Styles
COLORS = ['black', 'red', 'green', 'yellow',
          'blue', 'magenta', 'cyan', 'white']

STYLES = ['reset', 'bold', 'dim', 'italic', 'underline', 'blink-slow',
          'blink-rapid', 'reverse', 'hidden']

def get_index(target, value):
    try:
        return str(target.index(value))
    except:
        return "0"

def colorize(string, fore_color='black', background=None, style=None):

    # Background
    if background is None:
        background_option = ''
    else:
        background_option = '4' + COLORS.get(background, '0') + ';'

    # Style
    if type(style) in [list, tuple]:
        style_option = "".join(
            [";" + get_index(STYLES, i) for i in style])
    elif isinstance(style, basestring):
        style_option = ";" + get_index(STYLES, style)
    else:
        style_option = ';22'

    return "\033[%s3%s%sm%s\033[0m" % (
        background_option,
        get_index(COLORS, fore_color),
        style_option,
        str(string)
    )
