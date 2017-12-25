# -*- coding:utf-8 -*-
from app import app
from views import *

# 测试环境
if __name__ == '__main__':
	app.run(host='127.0.0.1',port=8888)