from index import aes
import json
from os import getenv

aeskey=getenv('aeskey')

with open('test/thread.json', 'r') as f:
    d=f.read()

r=aes.encrypt(d, aeskey)

with open('.data/thread', 'wb') as f:
    f.write(r)

del d, r

with open('test/user.json', 'r') as f:
    d=f.read()
    
r=aes.encrypt(d, aeskey)

with open('.data/user', 'wb') as f:
    f.write(r)

del d, r

with open('test/image.json', 'r') as f:
    d=f.read()

r=aes.encrypt(d, aeskey)

with open('.data/image', 'wb') as f:
    f.write(r)

print('EOF')