# -*- coding:utf-8 -*-
from app import cer
from base import readCER
from flask import render_template,request

# 证书查看
@cer.route('/cer_check',methods=['POST'])
def cer_check():
    pem_data=request.form['cer_content'].encode('utf-8')
    return render_template('tools/cer_check_result.html',cer_content=readCER(pem_data))