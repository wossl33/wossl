# -*- coding:utf-8 -*-
from app import feis
from base import pubkey_tiqu,pubkey_asysi,pub_priv_checker,pub_priv_creater,private_xiugai
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

@feis.route('/web_pub_get',methods=['POST'])
def web_pub_get():
    key_content=request.form['key_content'].encode('utf-8')
    key=str(request.form['key'])
    if key:
        return render_template('web/public_get_result.html',tiqu_result=pubkey_tiqu(key_content,key))
    else:
        return render_template('web/public_get_result.html',tiqu_result=pubkey_tiqu(key_content))


# 公钥解析
@feis.route('/pub_asysi')
def pub_asysi():
    return render_template('feis/asysi.html')
# 公钥解析处理
@feis.route('/asysi_hander',methods=['POST'])
def asysi_hander():
    public_key_content=request.form['public_key_content'].encode('utf-8')
    return render_template('feis/asysi_result.html',rep_result=pubkey_asysi(public_key_content))

@feis.route('/web_pub_asysi',methods=['POST'])
def web_pub_asysi():
    public_key_content=request.form['public_key_content'].encode('utf-8')
    return render_template('web/public_asysi_result.html',rep_result=pubkey_asysi(public_key_content))

# 公私钥校验
@feis.route('/pub_priv')
def pub_priv():
    return render_template('feis/jiaoyan.html')

# 公私钥校验处理
@feis.route('/pub_priv_hander',methods=['POST'])
def pub_priv_hander():
    public_key=request.form['public_key'].encode('utf-8')
    private_key=request.form['private_key'].encode('utf-8')
    key=str(request.form['key'])
    if key:
        return render_template('feis/jiaoyan_result.html',jy_result=pub_priv_checker(public_key,private_key,key))
    else:
        return render_template('feis/jiaoyan_result.html',jy_result=pub_priv_checker(public_key,private_key))

# 公私钥校验处理
@feis.route('/web_pub_priv_hander',methods=['POST'])
def web_pub_priv_hander():
    public_key=request.form['public_key'].encode('utf-8')
    private_key=request.form['private_key'].encode('utf-8')
    key=str(request.form['key'])
    if key:
        return render_template('web/pub_priv_jy_result.html',jy_result=pub_priv_checker(public_key,private_key,key))
    else:
        return render_template('web/pub_priv_jy_result.html',jy_result=pub_priv_checker(public_key,private_key))    

# 密钥对生成
@feis.route('/pub_key_create')
def pub_key_create():
    return render_template('feis/pub_priv_double.html')

@feis.route('/pub_priv_create_hander',methods=['POST'])
def pub_priv_create_hander():
    mysf=str(request.form['mysf'])
    if str(request.form['myqd']):
        myqd=str(request.form['myqd'])
    elif mysf == 'ECDSA' and not str(request.form['myqd']):
        myqd='P256'
    else:
        myqd='2048'
    key_pass=str(request.form['key_pass'])
    return render_template('feis/pub_priv_double_result.html',result=pub_priv_creater(mysf,myqd,key_pass))


@feis.route('/web_pass_hander',methods=['POST'])
def web_pass_hander():
    mysf=str(request.form['mysf'])
    if str(request.form['myqd']):
        myqd=str(request.form['myqd'])
    elif mysf == 'ECDSA' and not str(request.form['myqd']):
        myqd='P256'
    else:
        myqd='2048'
    key_pass=str(request.form['key_pass'])
    return render_template('web/pass_double_result.html',result=pub_priv_creater(mysf,myqd,key_pass))

# 私钥密码修改
@feis.route('/priv_xiugai')
def priv_xiugai():
    return render_template('feis/priv_xiugai.html')

@feis.route('/priv_xg_hander',methods=['POST'])
def priv_xg_hander():
    private_key=request.form['priv_content'].encode('utf-8')
    old_key=str(request.form['old_key'])
    new_key=str(request.form['new_key'])
    return render_template('feis/priv_xiugai_result.html',key_reuslt=private_xiugai(private_key,old_key,new_key))

@feis.route('/web_priv_xg',methods=['POST'])
def web_priv_xg():
    private_key=request.form['priv_content'].encode('utf-8')
    old_key=str(request.form['old_key'])
    new_key=str(request.form['new_key'])
    return render_template('web/priv_xg_result.html',key_reuslt=private_xiugai(private_key,old_key,new_key))