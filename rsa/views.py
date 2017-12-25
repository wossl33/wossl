# -*- coding:utf-8 -*-
from app import rsa
from base import cer_csr,cer_key,csr_key,jjm_1,jjm_2
from flask import render_template,request

@rsa.route('/rsa_check',methods=['POST'])
def rsa_check():
    req_cer_csr=request.form['cer_csr'].encode('utf-8')
    csr_pri=request.form['csr_pri'].encode('utf-8')
    key=str(request.form['key'])
    if int(request.form['suite_type']) == 1:
        if key:
            return render_template('tools/rsa_check_result.html',rsa_check_r=cer_key(req_cer_csr,csr_pri,key))
        else:
            return render_template('tools/rsa_check_result.html',rsa_check_r=cer_key(req_cer_csr,csr_pri))
    elif int(request.form['suite_type']) == 2:
        return render_template('tools/rsa_check_result.html',rsa_check_r=cer_csr(req_cer_csr,csr_pri))
    elif int(request.form['suite_type']) == 3:
        if key:
            return render_template('tools/rsa_check_result.html',rsa_check_r=csr_key(req_cer_csr,csr_pri,key))
        else:
            return render_template('tools/rsa_check_result.html',rsa_check_r=csr_key(req_cer_csr,csr_pri))
    else:
        return render_template('tools/rsa_check_result.html',rsa_check_r={'msg':u'校验类型有误！'})

@rsa.route('/pre_cer',methods=['POST'])
def pre_cer():
    priv_content=request.form['priv_content'].encode('utf-8')
    key=str(request.form['key'])
    if int(request.form['jjm_type']) == 1:
        return render_template('tools/pre_cer_result.html',key_reuslt=jjm_1(priv_content,key))
    elif int(request.form['jjm_type']) == 2:
        return render_template('tools/pre_cer_result.html',key_reuslt=jjm_2(priv_content,key))
    else:
        return render_template('tools/pre_cer_result.html',key_reuslt={'error':True,'msg':u'异常错误！'})