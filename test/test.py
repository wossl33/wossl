from OpenSSL import crypto

def gen_pkcs12(cert_pem=None,key_pem=None,ca_pem=None,friendly_name=None):
    p12=crypto.PKCS12()
    if cert_pem:
        ret = p12.set_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
        assert ret is None
    if key_pem:
        ret = p12.set_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem))
        assert ret is None
    if ca_pem:
        ret = p12.set_ca_certificates(
                (crypto.load_certificate(crypto.FILETYPE_PEM, ca_pem),)
            )
        assert ret is None
    if friendly_name:
        ret = p12.set_friendlyname(friendly_name)
        assert ret is None
    return p12

if __name__=='__main__':
    cer_pem_data=b''
    key_pem_data=b''
    try:
        with open('./whcrc.cer','rb') as f:
            cer_pem_data=f.read()
    except Exception as e:
        print(e)

    try:
        with open('./key.pem','rb') as f:
            key_pem_data=f.read()
    except Exception as e:
        print(e)
    
    print gen_pkcs12(cer_pem_data,key_pem_data).export()