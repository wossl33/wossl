# -*- coding:utf-8 -*-
from flask import Flask
from cer import cer
from csr import csr
from rsa import rsa
from des import des
from hashs import hashs
from feis import feis

app=Flask(__name__)

# 加载配置文件
app.config.from_pyfile('config.py')

# 注册蓝图
app.register_blueprint(cer,url_prefix='/cer')
app.register_blueprint(csr,url_prefix='/csr')
app.register_blueprint(rsa,url_prefix='/rsa')
app.register_blueprint(des,url_prefix='/des')
app.register_blueprint(hashs,url_prefix='/hashs')
app.register_blueprint(feis,url_prefix='/feis')