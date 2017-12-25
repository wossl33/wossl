# -*- coding:utf-8 -*-
# 生产环境Gunicorn部署Flask应用
from app import app
from views import *

if __name__ == '__main__':
    from werkzeug.contrib.fixers import ProxyFix
    app.wsgi_app=ProxyFix(app.wsgi_app)
    app.run()