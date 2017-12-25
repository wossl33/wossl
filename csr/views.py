# -*- coding:utf-8 -*-
from app import csr
from base import readCSR,create_csr
from flask import render_template,request

# CSR查看
@csr.route('/csr_check',methods=['POST'])
def csr_check():
    pem_data=request.form['csr_content'].encode('utf-8')
    return render_template('tools/csr_check_result.html',csr_content=readCSR(pem_data))

# CSR创建
@csr.route('/csr_create',methods=['POST'])
def csr_create():
    com_name=request.form['com_name'].encode('utf-8').decode('utf-8')
    bumen_name=request.form['bumen_name'].encode('utf-8').decode('utf-8')
    zuzhi_name=request.form['zuzhi_name'].encode('utf-8').decode('utf-8')
    city_name=request.form['city_name'].encode('utf-8').decode('utf-8')
    shengfen_name=request.form['shengfen_name'].encode('utf-8').decode('utf-8')
    guojia_name=request.form['guojia_name'].encode('utf-8').decode('utf-8')
    beiyong_name=request.form['beiyong_name'].encode('utf-8').decode('utf-8')
    mysf=str(request.form['mysf'])
    if str(request.form['myqd']):
        myqd=str(request.form['myqd'])
    elif mysf == 'ECDSA' and not str(request.form['myqd']):
        myqd='P256'
    else:
        myqd='2048'
    
    if str(request.form['qmsf']):
        qmsf=str(request.form['qmsf'])
    else:
        qmsf='SHA1'
    key_pass=str(request.form['key_pass'])
    return render_template('tools/csr_create_result.html',result=create_csr(com_name,bumen_name,zuzhi_name,city_name,shengfen_name,guojia_name,mysf,beiyong_name,myqd,qmsf,key_pass))