# -*- coding:utf-8 -*-
from app import csr
from base import readCSR,create_csr,create_cert
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


# 自签名证书
@csr.route('/cert_create_hander',methods=['POST'])
def cert_create_hander():
    # 主题信息
    subject_com_name=request.form['subject_com_name'].encode('utf-8').decode('utf-8')
    subject_bumen_name=request.form['subject_bumen_name'].encode('utf-8').decode('utf-8')
    subject_zuzhi_name=request.form['subject_zuzhi_name'].encode('utf-8').decode('utf-8')
    subject_city_name=request.form['subject_city_name'].encode('utf-8').decode('utf-8')
    subject_shengfen_name=request.form['subject_shengfen_name'].encode('utf-8').decode('utf-8')
    subject_guojia_name=request.form['subject_guojia_name'].encode('utf-8').decode('utf-8')
    beiyong_name=request.form['beiyong_name'].encode('utf-8').decode('utf-8')
    # 颁布者信息
    issuer_com_name=request.form['issuer_com_name'].encode('utf-8').decode('utf-8')
    issuer_zuzhi_name=request.form['issuer_zuzhi_name'].encode('utf-8').decode('utf-8')
    issuer_guojia_name=request.form['issuer_guojia_name'].encode('utf-8').decode('utf-8')
    # 证书信息
    before_time=str(request.form['before_time'])
    after_time=str(request.form['after_time'])
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
    try:
        root=request.form['root']
        return render_template('tools/cert_create_result.html',result=create_cert(subject_com_name,subject_bumen_name,subject_zuzhi_name,subject_city_name,subject_shengfen_name,subject_guojia_name,issuer_com_name,issuer_zuzhi_name,issuer_guojia_name,True,before_time,after_time,mysf,beiyong_name,myqd,qmsf,key_pass))
    except Exception,e:
        return render_template('tools/cert_create_result.html',result=create_cert(subject_com_name,subject_bumen_name,subject_zuzhi_name,subject_city_name,subject_shengfen_name,subject_guojia_name,issuer_com_name,issuer_zuzhi_name,issuer_guojia_name,False,before_time,after_time,mysf,beiyong_name,myqd,qmsf,key_pass))
        