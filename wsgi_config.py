# -*- coding:utf-8 -*-
# wossl.service加载配置文件
import os
import gevent.monkey
gevent.monkey.patch_all()

import multiprocessing

debug=True
loglevel='debug'
bind='192.168.85.81:8080'
pidfile='/tmp/gunicorn.pid'
logfile='/tmp/debug.log'
# 多核多线程
workers = multiprocessing.cpu_count()*2 + 1
worker_class = 'gunicorn.workers.ggevent.GeventWorker'
