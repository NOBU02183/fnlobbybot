from index import aes
import json
from os import getenv

aeskey=getenv('aeskey')

with open('.data/thread', 'rb') as f:
    d=f.read()

r=json.loads(aes.decrypt(d, aeskey))

with open('test/thread.json', 'w') as f:
    json.dump(r, f, indent='\t', ensure_ascii=False)

del d, r

with open('.data/user', 'rb') as f:
    d=f.read()

r=json.loads(aes.decrypt(d, aeskey))

with open('test/user.json', 'w') as f:
    json.dump(r, f, indent='\t', ensure_ascii=False)

del d, r

with open('.data/image', 'rb') as f:
    d=f.read()

r=json.loads(aes.decrypt(d, aeskey))

with open('test/image.json', 'w') as f:
    json.dump(r, f, indent='\t', ensure_ascii=False)

print('EOF')