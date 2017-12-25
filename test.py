from socket import socket
from OpenSSL.SSL import Connection,Context,SSLv23_METHOD
from OpenSSL import _util

ssl_context=Context(SSLv23_METHOD)
ssl_context.set_cipher_list("ALL:COMPLEMENT")
conn = Connection(ssl_context)
cipher_ptr = _util.lib.SSL_get_ciphers(conn._ssl)
for i in range(_util.lib.sk_SSL_CIPHER_num(cipher_ptr)):
    cipher = _util.lib.sk_SSL_CIPHER_value(cipher_ptr, i)
    print _util.ffi.string(_util.lib.SSL_CIPHER_get_name(cipher))

'''
ssl_context.set_timeout(30)
ip='113.57.133.147'
port=443
s=socket()
s.connect((ip,port))
c=Connection(ssl_context,s)
c.set_connect_state()
print "%s try to handshake" % (ip)
c.do_handshake()
cert = c.get_peer_certificate()
print "issuer: ",cert.get_issuer()
print "subject: ",cert.get_subject().get_components()
c.shutdown()
s.close()
'''