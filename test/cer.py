# -*- coding:utf-8 -*-
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,dsa,ec
from base import split_string
import binascii

def readCER(pem_req_data):
    cer=None
    try:
        cer=x509.load_pem_x509_certificate(pem_req_data,default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'证书内容错误！'}
    if isinstance(cer,x509.Certificate):
        rep_result={}
        # 获取subject基本信息
        subject_check=['commonName','countryName','stateOrProvinceName','localityName','organizationName','organizationalUnitName']
        for attr in cer.subject:
            if attr.oid._name in subject_check:
                rep_result[attr.oid._name]=attr.value
                subject_check.remove(attr.oid._name)
            
        for i in subject_check:
            rep_result[i]=""
        # 获取颁布者信息
        issuer_check=['commonName','countryName','stateOrProvinceName','localityName','organizationName','organizationalUnitName']
        for attr in cer.issuer:
            if attr.oid._name in issuer_check:
                rep_result['i_'+attr.oid._name]=attr.value
                issuer_check.remove(attr.oid._name)
        for i in issuer_check:
            rep_result['i_'+i]=''
        # 获取证书信息
        rep_result['cert_serial_number']=cer.serial_number
        # 获取密钥强度
        rep_result['public_key_size']=str(cer.public_key().key_size)
        # 证书指纹
        rep_result['cert_hash_sha1']=binascii.hexlify(cer.fingerprint(hashes.SHA1()))
        rep_result['cert_hash_sha256']=binascii.hexlify(cer.fingerprint(hashes.SHA256()))
        # 获取加密校验算法
        if isinstance(cer.public_key(),rsa.RSAPublicKey):
            rep_result['public_key']="RSA"
            rep_result['public_key_n']=split_string(cer.public_key().public_numbers().n,64)
            rep_result['public_key_e']=cer.public_key().public_numbers().e
        elif isinstance(cer.public_key(),dsa.DSAPublicKey):
            rep_result['public_key']="DSA"
            rep_result['public_key_y']=split_string(cer.public_key().public_numbers().y,64)
        elif isinstance(cer.public_key(),ec.EllipticCurvePublicKey):
            rep_result['public_key']="ECDSA"
            rep_result['public_key_x']=split_string(cer.public_key().public_numbers().x,64)
            rep_result['public_key_y']=split_string(cer.public_key().public_numbers().y,64)
        else:
            rep_result['public_key']=""
        # 签名算法
        if isinstance(cer.signature_hash_algorithm,hashes.MD5):
            rep_result['sign_with']="MD5"
        elif isinstance(cer.signature_hash_algorithm,hashes.SHA1):
            rep_result['sign_with']="SHA1"
        elif isinstance(cer.signature_hash_algorithm,hashes.SHA224):
            rep_result['sign_with']="SHA224"
        elif isinstance(cer.signature_hash_algorithm,hashes.SHA256):
            rep_result['sign_with']="SHA256"
        elif isinstance(cer.signature_hash_algorithm,hashes.SHA384):
            rep_result['sign_with']="SHA384"
        elif isinstance(cer.signature_hash_algorithm,hashes.SHA512):
            rep_result['sign_with']="SHA512"
        elif isinstance(cer.signature_hash_algorithm,hashes.BLAKE2b):
            rep_result['sign_with']="BLAKE2b"
        elif isinstance(cer.signature_hash_algorithm,hashes.BLAKE2s):
            rep_result['sign_with']="BLAKE2s"
        else:
            rep_result['sign_with']=""
        # 颁发时间和过期时间
        rep_result['cert_not_valid_before']=str(cer.not_valid_before)
        rep_result['cert_not_valid_after']=str(cer.not_valid_after)
        rep_result['cert_valid_days']=(cer.not_valid_after-cer.not_valid_before).days
        # 签名信息
        rep_result['cer_signture']=split_string(binascii.hexlify(cer.signature),64)
        # 证书扩展信息
        for extension in cer.extensions:
            if isinstance(extension.value,x509.KeyUsage):
                # 暂时不做处理
                pass
            elif isinstance(extension.value,x509.AuthorityInformationAccess):
                if extension.value:
                    for j in extension.value:
                        if j.access_method._name == 'caIssuers':
                            rep_result['cert_ca_url']=j.access_location.value
                        elif j.access_method._name == 'OCSP':
                            rep_result['cert_ca_ocsp']=j.access_location.value
                        else:
                            rep_result['cert_ca_url']=''
                            rep_result['cert_ca_ocsp']=''
            elif isinstance(extension.value,x509.CertificatePolicies):
                # 证书地址
                pass
            elif isinstance(extension.value,x509.BasicConstraints):
                # 判断是否是根证书
                if extension.value.ca:
                    rep_result['cert_ca_not']=u'是'
                else:
                    rep_result['cert_ca_not']=u'否'
            elif isinstance(extension.value,x509.SubjectAlternativeName):
                # 读取备用信息
                if extension.value:
                    j=[]
                    for i in extension.value:
                        if isinstance(i,x509.DNSName):
                            j.append(i.value)
                    rep_result['cert_extent_info']='\n'.join(j)
                else:
                    rep_result['cert_extent_info']=''
            elif isinstance(extension.value,x509.ExtendedKeyUsage):
                # 证书用途
                if extension.value:
                    j=[]
                    for i in extension.value:
                        j.append(i._name)
                    rep_result['cert_for_who']=','.join(j)
                else:
                    rep_result['cert_for_who']=''
            elif isinstance(extension.value,x509.SubjectKeyIdentifier):
                pass
            elif isinstance(extension.value,x509.CRLDistributionPoints):
                if extension.value:
                    for i in extension.value:
                        if len(i.full_name) <=1:
                            rep_result['cert_crl_url']=''.join([k.value for k in i.full_name])
                        else:
                            rep_result['cert_crl_url']=''.join([k.value for k in i.full_name])
                else:
                    rep_result['cert_crl_url']=''
            else:
                pass
        # 公钥明文
        rep_result['public_key_string']=cer.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'error':True,'msg':rep_result}
    else:
        return {'error':False,'msg':u'对象类型错误！'}

if __name__=='__main__':
    pem_data=b''
    try:
        with open('./test.cer','rb') as f:
            pem_data=f.read()
    except Exception as e:
        print(e)
    print readCER(pem_data)