from Crypto.Hash import HMAC
s='sworld'
h=HMAC.new(s)
h.update('hello')
print h.hexdigest()