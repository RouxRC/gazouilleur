#!/usr/bin/env python
# -*- coding: utf-8 -*-
# punchcard drawing adapted from HgPunchcard (GPL 2+ https://bitbucket.org/birkenfeld/hgpunchcard/src/f4d38c737147cdf966909c2957a79573a6a5c517/hgpunchcard.py?at=default )
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pylab import *
from matplotlib.ticker import Formatter, MaxNLocator
from matplotlib.dates import DayLocator

days = 'Mon Tue Wed Thu Fri Sat Sun'.split()

def CumulativeCurve(x_data, y_data, titl, path, filename):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.plot(x_data, y_data)
    ax.grid(True, fillstyle='left')
    fig.autofmt_xdate()
    ax.xaxis.set_major_locator(MaxNLocator(13))
    ax.xaxis.set_minor_locator(DayLocator())
    title(titl)
    fig.savefig(os.path.join(path, "%s.png" % filename))
    fig.clf()
    plt.close(fig)

def DailyHistogram(x_data, y_data, titl, path, filename):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    n1 = 0; n2 = 0
    d1 = []; d2 = []
    v1 = []; v2 = []
    for i, a in enumerate(x_data):
        n1 += y_data[i]
        n2 += y_data[i]
        if i % 4 == 1:
            a2 = a
        elif i % 4 == 3:
            d2.append(a2)
            v2.append(n2)
            n2 = 0
        if i % 24 == 11:
            a1 = a
        elif i % 24 == 23:
            d1.append(a1)
            v1.append(n1)
            n1 = 0
    ax.plot(d1, v1, drawstyle='steps-pre')
    ax.grid(True)
    fig.autofmt_xdate()
    ax.xaxis.set_major_locator(MaxNLocator(13))
    ax.xaxis.set_minor_locator(DayLocator())
    ax.plot(d2, v2, 'b', alpha=0.3, drawstyle='steps-pre')
    title(titl)
    fig.savefig(os.path.join(path, "%s.png" % filename))
    fig.clf()
    plt.close(fig)

def WeekPunchCard(dates, data, titl, path, filename):
    stats = [[0] * 24 for i in range(7)]
    for i, date in enumerate(dates):
        day = (int(date.strftime('%w')) - 1) % 7
        stats[day][date.hour] += data[i]
    maxvalue = max(max(i) for i in stats) or 1
    xs, ys, rs, ss = [], [], [], []
    for y, d in enumerate(stats):
        for x, n in enumerate(d):
            xs.append(x);
            ys.append(y);
            rs.append(13.*n/maxvalue)
            ss.append(4.*n**2/maxvalue)
    fig = plt.figure(figsize=(8, titl and 3 or 2.5), facecolor='#efefef')
    ax = fig.add_subplot('111', axisbg='#efefef')
    if titl:
        fig.subplots_adjust(left=0.06, bottom=0.04, right=0.98, top=0.95)
        ax.set_title(titl, y=0.96).set_color('#333333')
    else:
        fig.subplots_adjust(left=0.06, bottom=0.08, right=0.98, top=0.99)
    ax.set_frame_on(False)
    ax.scatter(xs, ys[::-1], s=ss, c='#333333', edgecolor='#333333')
    for line in ax.get_xticklines() + ax.get_yticklines():
        line.set_alpha(0.0)
    dist = -0.8
    ax.plot([dist, 23.5], [dist, dist], c='#555555')
    ax.plot([dist, dist], [dist, 6.4], c='#555555')
    ax.set_xlim(-1, 24)
    ax.set_ylim(-0.9, 6.9)
    ax.set_yticks(range(7))
    for tx in ax.set_yticklabels(days[::-1]):
        tx.set_color('#555555')
        tx.set_size('x-small')
    ax.set_xticks(range(24))
    for tx in ax.set_xticklabels(['%02d' % x for x in range(24)]):
        tx.set_color('#555555')
        tx.set_size('x-small')
    # get equal spacing for days and hours
    ax.set_aspect('equal')
    fig.savefig(os.path.join(path, "%s.png" % filename))
    fig.clf()
    plt.close(fig)

