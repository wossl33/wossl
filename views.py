# -*- coding:utf-8 -*-
from flask import Flask,render_template,request
from app import app
from cer import views as cer_views

# 首页
@app.route('/')
def index():
    # 测试环境下获取客户端IP
    client_ip=request.remote_addr
    # 生产环境下获取客户端IP
    '''
    if request.headers['X-Real-IP']:
        client_ip=request.headers['X-Real-IP']
    else:
        client_ip=request.headers['X-Forwarded-For']
    '''
    return render_template('index.html',client_ip=client_ip)

# 控制台
@app.route('/this_console')
def this_console():
    return render_template('console.html')

# SSL深度检查
@app.route('/gmssl')
def gmssl():
    return render_template('gmssl.html')

# 登录日志
@app.route('/log')
def log():
    return render_template('logs.html')

# 关于
@app.route('/abort')
def abort():
    return render_template('abort.html')

# 主页侧边栏--AES加解密
@app.route('/aes_cipher')
def aes_cipher():
    return render_template('tools/aes_cipher.html')
@app.route('/des_cipher')
def des_cipher():
    return render_template('tools/des_cipher.html')
@app.route('/tdes_cipher')
def tdes_cipher():
    return render_template('tools/3des_cipher.html')

# 主页侧边栏--证书工具
@app.route('/csr_check')
def csr_check():
    return render_template('tools/csr_check.html')
@app.route('/csr_create')
def csr_create():
    return render_template('tools/csr_create.html')
@app.route('/cer_check')
def cer_check():
    return render_template('tools/cer_check.html')
@app.route('/rsa_check')
def rsa_check():
    return render_template('tools/rsa_check.html')
@app.route('/pre_cer')
def pre_cer():
    return render_template('tools/pre_cer.html')
@app.route('/cert_create')
def cert_create():
    return render_template('tools/cert_create.html')

# 主页侧边栏--漏洞检测
@app.route('/vuls_check')
def vuls_check():
    return render_template('ssl/vuls_check.html')
@app.route('/ssl_woshou')
def ssl_woshou():
    return render_template('ssl/ssl_woshou.html')
@app.route('/ssl_xieyi_taojian')
def ssl_xieyi_taojian():
    return render_template('ssl/ssl_suites.html')
@app.route('/ssl_deep')
def ssl_deep():
    return render_template('ssl/ssl_deep.html')

# 底栏