# -*- coding:utf-8 -*-
from app import hashs
from base import md_sha_hash,hmac_hash
from flask import render_template,request

@hashs.route('/cry_hash')
def cry_hash():
    return render_template('tools/hash.html')

@hashs.route('/sha_hash',methods=['POST'])
def sha_hash():
    text=bytes(request.form['text'].encode('utf-8'))
    hash_flag=str(request.form['hash'])
    if hash_flag == 'HMAC':
        key=bytes(request.form['key'])
        return render_template('tools/hash_result.html',flag=hash_flag,hash_result=hmac_hash(text,key))
    return render_template('tools/hash_result.html',flag=hash_flag,hash_result=md_sha_hash(hash_flag,text))