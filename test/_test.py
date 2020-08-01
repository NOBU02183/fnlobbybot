from index import aes
import json

#with open('.data/thread', 'r', encoding='utf-8') as f:
#    d=f.read()
#
#r=aes.encrypt(d)
#
#with open('.data/thread', 'wb') as f:
#    f.write(r)
#
#with open('test.json', 'r', encoding='utf-8') as f:
#    bd=json.load(f)
#
#r=aes.encrypt(json.dumps(bd, indent='\t'))
#
#with open('.data/thread', 'wb') as f:
#    f.write(r)
#
#with open('.data/thread', 'rb') as f:
#    d2=f.read()
#
##print(aes.decrypt(d2).decode())
#print(json.loads(aes.decrypt(d2).decode()))

with open('.data/user', 'r', encoding='utf-8') as f:
    d=f.read()
r=aes.encrypt(d)
with open('.data/user', 'wb') as f:
    f.write(r)

print('End')