# -*- coding:utf-8 -*-
from app import des
from base import encrypt,decrypt
from flask import render_template,request

@des.route('/aes_encrypt',methods=['POST'])
def aes_encrypt():
    text=bytes(request.form['text'].encode('utf-8'))
    key=bytes(request.form['key'])
    mode=request.form['mode']
    iv=bytes(request.form['iv'])
    out_mode=request.form['out_mode']
    return render_template('tools/cipher_result.html',flag='AES',aes_result=encrypt(text,'AES',key,mode,iv,out_mode))

@des.route('/aes_decrypt',methods=['POST'])
def aes_decrypt():
    text=bytes(request.form['text'])
    key=bytes(request.form['key'])
    mode=request.form['mode']
    iv=bytes(request.form['iv'])
    out_mode=request.form['out_mode']
    return render_template('tools/cipher_result.html',flag='AES',aes_result=decrypt(text,'AES',key,mode,iv,out_mode))

@des.route('/des_encrypt',methods=['POST'])
def des_encrypt():
    text=bytes(request.form['text'].encode('utf-8'))
    key=bytes(request.form['key'])
    mode=request.form['mode']
    iv=bytes(request.form['iv'])
    out_mode=request.form['out_mode']
    return render_template('tools/cipher_result.html',flag='DES',aes_result=encrypt(text,'DES',key,mode,iv,out_mode))

@des.route('/des_decrypt',methods=['POST'])
def des_decrypt():
    text=bytes(request.form['text'])
    key=bytes(request.form['key'])
    mode=request.form['mode']
    iv=bytes(request.form['iv'])
    out_mode=request.form['out_mode']
    return render_template('tools/cipher_result.html',flag='DES',aes_result=decrypt(text,'DES',key,mode,iv,out_mode))

@des.route('/tdes_encrypt',methods=['POST'])
def tdes_encrypt():
    text=bytes(request.form['text'].encode('utf-8'))
    key=bytes(request.form['key'])
    mode=request.form['mode']
    iv=bytes(request.form['iv'])
    out_mode=request.form['out_mode']
    return render_template('tools/cipher_result.html',flag='3DES',aes_result=encrypt(text,'3DES',key,mode,iv,out_mode))

@des.route('/tdes_decrypt',methods=['POST'])
def tdes_decrypt():
    text=bytes(request.form['text'])
    key=bytes(request.form['key'])
    mode=request.form['mode']
    iv=bytes(request.form['iv'])
    out_mode=request.form['out_mode']
    return render_template('tools/cipher_result.html',flag='3DES',aes_result=decrypt(text,'3DES',key,mode,iv,out_mode))



