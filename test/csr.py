# -*- coding:utf-8 -*-
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,dsa,ec
from base import split_string
import binascii

# 读取CSR内容
def readCSR(pem_req_data):
    csr=None
    try:
        csr=x509.load_pem_x509_csr(pem_req_data,default_backend())
    except Exception,e:
        print e
        return {'error':False,'msg':u'CSR内容错误！'}
    # csr句柄获取
    if isinstance(csr,x509.CertificateSigningRequest):
        rep_reuslt={}
        # 获取subject基本信息
        subject_check=['commonName','countryName','stateOrProvinceName','localityName','organizationName','organizationalUnitName']
        for attr in csr.subject:
            if attr.oid._name in subject_check:
                rep_reuslt[attr.oid._name]=attr.value
                subject_check.remove(attr.oid._name)
            
        for i in subject_check:
            rep_reuslt[i]=""
        # csr扩展信息
        public_extensions=[]
        if csr.extensions:
            try:
                for extension in csr.extensions:
                    for value in extension.value:
                        if isinstance(value,x509.DNSName):
                            public_extensions.append(value.value)
                rep_reuslt['extension']=','.join(public_extensions)
            except Exception,e:
                print e
                return {'error':False,'msg':u'CSR扩展错误！'}
        else:
            rep_reuslt['extension']=''
        # 获取密钥强度
        rep_reuslt['public_key_size']=str(csr.public_key().key_size)
        # 密钥类型
        if isinstance(csr.public_key(),rsa.RSAPublicKey):
            rep_reuslt['public_key']="RSA"
            rep_reuslt['public_key_n']=split_string(csr.public_key().public_numbers().n,64)
            rep_reuslt['public_key_e']=csr.public_key().public_numbers().e
        elif isinstance(csr.public_key(),dsa.DSAPublicKey):
            rep_reuslt['public_key']="DSA"
            rep_reuslt['public_key_y']=split_string(csr.public_key().public_numbers().y,64)
        elif isinstance(csr.public_key(),ec.EllipticCurvePublicKey):
            rep_reuslt['public_key']="ECDSA"
            rep_reuslt['public_key_x']=split_string(csr.public_key().public_numbers().x,64)
            rep_reuslt['public_key_y']=split_string(csr.public_key().public_numbers().y,64)
        else:
            rep_reuslt['public_key']=""
        # 签名算法
        if isinstance(csr.signature_hash_algorithm,hashes.MD5):
            rep_reuslt['sign_with']="MD5"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA1):
            rep_reuslt['sign_with']="SHA1"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA224):
            rep_reuslt['sign_with']="SHA224"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA256):
            rep_reuslt['sign_with']="SHA256"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA384):
            rep_reuslt['sign_with']="SHA384"
        elif isinstance(csr.signature_hash_algorithm,hashes.SHA512):
            rep_reuslt['sign_with']="SHA512"
        elif isinstance(csr.signature_hash_algorithm,hashes.BLAKE2b):
            rep_reuslt['sign_with']="BLAKE2b"
        elif isinstance(csr.signature_hash_algorithm,hashes.BLAKE2s):
            rep_reuslt['sign_with']="BLAKE2s"
        else:
            rep_reuslt['sign_with']=""
        # 签名信息及是否有效
        rep_reuslt['csr_signture']=split_string(binascii.hexlify(csr.signature),64)
        if csr.is_signature_valid:
            rep_reuslt['csr_sign_valid']=u"是"
        else:
            rep_reuslt['csr_sign_valid']=u"否"
        # 公钥明文
        rep_reuslt['public_key_string']=csr.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'error':True,'msg':rep_reuslt}
    else:
        return {'error':False,'msg':u'对象类型错误！'}

if __name__=='__main__':
    pem_data=b''
    try:
        with open('./csr.pem','rb') as f:
            pem_data=f.read()
    except Exception as e:
        print(e)

    print readCSR(pem_data)