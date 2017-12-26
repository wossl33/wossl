# -*- coding:utf-8 -*-
from app import feis
from base import pubkey_tiqu,pubkey_asysi
from flask import request,render_template

# 公钥提取
@feis.route('/pub_tiqu')
def pub_tiqu():
    return render_template('feis/tiqu.html')
# 公钥提取处理
@feis.route('/tiqu_hander',methods=['POST'])
def tiqu_hander():
    key_content=request.form['key_content'].encode('utf-8')
    key=str(request.form['key'])
    if key:
        return render_template('feis/tiqu_result.html',tiqu_result=pubkey_tiqu(key_content,key))
    else:
        return render_template('feis/tiqu_result.html',tiqu_result=pubkey_tiqu(key_content))
# 公钥解析
@feis.route('/pub_asysi')
def pub_asysi():
    return render_template('feis/asysi.html')
# 公钥解析处理
@feis.route('/asysi_hander',methods=['POST'])
def asysi_hander():
    public_key_content=request.form['public_key_content'].encode('utf-8')
    return render_template('feis/asysi_result.html',rep_result=pubkey_asysi(public_key_content))
# 公钥加解密
@feis.route('/pub_jjm')
def pub_jjm():
    return render_template('feis/jiajiemi.html')
# 公私钥校验
@feis.route('/pub_priv')
def pub_priv():
    return render_template('feis/jiaoyan.html')
