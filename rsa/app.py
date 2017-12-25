# -*- coding:utf-8 -*-
from flask import Blueprint
#声明定义蓝图，初始化静态文件和模版的加载目录
rsa=Blueprint('rsa',__name__,static_folder='static',\
	template_folder='templates')