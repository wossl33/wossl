# -*- coding:utf-8 -*-
from flask import Flask,render_template,request
import csr
import cer
import rsa
import key

app = Flask(__name__)

# 首页
@app.route('/')
def index():
    client_ip=request.remote_addr
    return render_template('index.html',client_ip=client_ip)
# gmssl项目
@app.route('/gmssl')
def gmssl():
    return render_template('gmssl.html')
# 控制台
@app.route('/this_console')
def this_console():
    return render_template('console.html')

# 登录日志
@app.route('/log')
def log():
    return render_template('logs.html')

# 版本信息
@app.route('/banner')
def banner():
    return render_template('banner.html')

'''
 SSL工具集
'''
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
@app.route('/pro_suites')
def pro_suites():
    return render_template('tools/pro_suites.html')
'''
 SSL漏洞检测
'''
@app.route('/vuls_check')
def vuls_check():
    return render_template('vules/vuls_check.html')
@app.route('/heart_bleed')
def heart_bleed():
    return render_template('vules/heart_bleed.html')
@app.route('/freak_attack')
def freak_attack():
    return render_template('vules/freak_attack.html')
@app.route('/ssl_poodle')
def ssl_poodle():
    return render_template('vules/ssl_poodle.html')
@app.route('/ccs_injection')
def ccs_injection():
    return render_template('vules/ccs_injection.html')
@app.route('/cbc_padding')
def cbc_padding():
    return render_template('vules/cbc_padding.html')
@app.route('/csr_check_show',methods=['POST'])
def csr_check_show():
    pem_data=request.form['csr_content'].encode('utf-8')
    return render_template('tools/csr_check_result.html',csr_content=csr.readCSR(pem_data))
@app.route('/cer_check_show',methods=['POST'])
def cer_check_show():
    pem_data=request.form['cer_content'].encode('utf-8')
    return render_template('tools/cer_check_result.html',cer_content=cer.readCER(pem_data))
@app.route('/rsa_check_show',methods=['POST'])
def rsa_check_show():
    req_cer_csr=request.form['cer_csr'].encode('utf-8')
    csr_pri=request.form['csr_pri'].encode('utf-8')
    key=str(request.form['key'])
    if int(request.form['suite_type']) == 1:
        if key:
            return render_template('tools/rsa_check_result.html',rsa_check_r=rsa.cer_key(req_cer_csr,csr_pri,key))
        else:
            return render_template('tools/rsa_check_result.html',rsa_check_r=rsa.cer_key(req_cer_csr,csr_pri))
    elif int(request.form['suite_type']) == 2:
        return render_template('tools/rsa_check_result.html',rsa_check_r=rsa.cer_csr(req_cer_csr,csr_pri))
    elif int(request.form['suite_type']) == 3:
        if key:
            return render_template('tools/rsa_check_result.html',rsa_check_r=rsa.csr_key(req_cer_csr,csr_pri,key))
        else:
            return render_template('tools/rsa_check_result.html',rsa_check_r=rsa.csr_key(req_cer_csr,csr_pri))
    else:
        return render_template('tools/rsa_check_result.html',rsa_check_r={'msg':u'校验类型有误！'})
@app.route('/pre_cer_result',methods=['POST'])
def pre_cer_result():
    priv_content=request.form['priv_content'].encode('utf-8')
    key=str(request.form['key'])
    if int(request.form['jjm_type']) == 1:
        return render_template('tools/pre_cer_result.html',key_reuslt=rsa.jjm_1(priv_content,key))
    elif int(request.form['jjm_type']) == 2:
        return render_template('tools/pre_cer_result.html',key_reuslt=rsa.jjm_2(priv_content,key))
    else:
        return render_template('tools/pre_cer_result.html',key_reuslt={'error':True,'msg':u'异常错误！'})

@app.route('/create_csr',methods=['POST'])
def create_csr():
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
    return render_template('tools/csr_create_result.html',result=key.create_csr(com_name,bumen_name,zuzhi_name,city_name,shengfen_name,guojia_name,mysf,beiyong_name,myqd,qmsf,key_pass))
 
if __name__ == '__main__':
    app.debug=True
    app.run()
