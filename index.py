# -*- coding: utf-8 -*-

#やあ ここで何してるんだい？

from sanic import Sanic
from sanic import response as res
from sanic.exceptions import abort
from sanic.websocket import ConnectionClosed
from jinja2 import Environment, FileSystemLoader, Markup
import os
import json
from Crypto.Cipher import AES
import random, string
from uuid import uuid4
import requests
import aiohttp
from time import ctime as time
import logging
import sys
from sanic.log import logger as saniclogger
import re
from asyncio import sleep

app=Sanic(__name__)
expires={}
admins=['0', '1']

url_pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"

jinja2env=Environment(loader=FileSystemLoader('./html', encoding='utf8'))

class discordlogginghandler(logging.Handler):

    def __init__(self):
        logging.Handler.__init__(self)
        #fmt=logging.Formatter('%(asctime)s - (%(name)s)[%(levelname)s][%(host)s]: %(request)s %(message)s %(status)d %(byte)d')
        
    def emit(self, record):
        #print(record)
        c=self.format(record)
        print(c)
        sendtodc(c, channel_id=738943877699993631)

#dlh=discordlogginghandler()
#rootlogger=logging.getLogger()
#rootlogger.addHandler(dlh)
dlh=discordlogginghandler()
#dlh.setFormatter(logging.Formatter('%(asctime)s - (%(name)s)[%(levelname)s][%(host)s]: %(request)s %(message)s %(status)d %(byte)d'))
#logging.getLogger('sanic.root').addHandler(dlh)
#logging.getLogger('sanic.error').addHandler(dlh)
#logging.getLogger('sanic.access').addHandler(dlh)
if saniclogger.handlers:
    for i in saniclogger.handlers:
        saniclogger.removeHandler(i)
dlh.setLevel(10)
saniclogger.setLevel(10)
saniclogger.addHandler(dlh)

def render_html(file_, **kwargs) -> str:
    template = jinja2env.get_template(file_)
    return res.html(template.render(**kwargs))
    
def replaceurl(s):
    url_list = re.findall(url_pattern, s)
    if not url_list:
    	return s
    for i in url_list:
    	s=s.replace(i, f'<a href="{i}">{i}</a>', 1)
    return s

class thread():
    
    def getall():
        t=json.loads(aes.readfile('.data/thread'))
        return t

    def getthread(threadid):
        return thread.getall()[threadid]

    def post(threadid, useruuid, content, images=None):
        if images:
            imagesr=image.createurl(images)
        else:
            imagesr=None
        t=thread.getthread(threadid)
        t['messages'].append(
            {
                'authoruuid':useruuid,
                'content':replaceurl(content),
                'time':time(),
                'image':[{'id':i} for i in imagesr] if imagesr else None
            }
        )
        r=thread.getall()
        r[threadid]=t
        aes.writefile('.data/thread', json.dumps(r, indent='\t', ensure_ascii=False))
        sendtodc(f'スレッド {threadid} の新規メッセージ\nユーザー: {useruuid}\n{content}')
        return True
        
    def create(useruuid, name, content, images=None):
        if images:
            imagesr=image.createurl(images)
        else:
            imagesr=None
        r=thread.getall()
        threadid=uuid()
        r[threadid]={
            "name": name,
		    "creatoruuid": useruuid,
            'time':time(),
		    "messages": [
                {
                    'authoruuid':useruuid,
                    'content':replaceurl(content),
                    'time':time(),
                    'image':[{'id':i} for i in imagesr] if imagesr else None
                }
            ]
        }
        aes.writefile('.data/thread', json.dumps(r, indent='\t', ensure_ascii=False))
        sendtodc(f'新規スレッド {name}\nユーザー: {useruuid}\n{content}')
        return threadid
        
    def delete(threadid):
        if threadid in (threads:=thread.getall()).keys():
            del threads[threadid]
            aes.writefile('.data/thread', json.dumps(threads, indent='\t', ensure_ascii=False))
            sendtodc(f'スレッド削除 {threadid}')
            return True
        else:
            return False

class user():

    def getall():
        u=json.loads(aes.readfile('.data/user'))
        #print(u)
        r={}
        for i in u.keys():
            r.update(
                {
                    u[i]['userid']:{
                        **u[i],
                        'useruuid':i
                    }
                }
            )
        return r

    def getall_uuid():
        u=json.loads(aes.readfile('.data/user'))
        return u

    def getuser(userid):
        return user.getall()[userid]
        
    def getuuid(userid):
        return user.getall().get(userid, {}).get('useruuid', False)
        
    def isadmin(userid):
        return user.getuuid(userid) in admins
        #r=user.getuuid(userid) in admins
        #print('isadmin:', userid, r)
        #return r

    def change(userid, changetype, content):
        if (userdata:=user.getall().get(userid, False)):
            useruuid=userdata.pop('useruuid')
            if changetype == 'name':
                userdata['name']=content
            elif changetype == 'id':
                userdata['userid']=content
            elif changetype == 'password':
                userdata['password']=content
            r=user.getall_uuid()
            r[useruuid]=userdata
            #with open('test/r.txt', 'w') as f:
            #    f.write(str(locals()))
            data=json.dumps(r, indent='\t', ensure_ascii=False)
            aes.writefile('.data/user', data)
            return True
        else:
            return False

class image():

    def getall():
        r=json.loads(aes.readfile('.data/image'))
        return r
    
    def post(images):
        channel_id = 735514064356376636
        API_BASE = "https://discordapp.com/api/v7"
        MESSAGE = f"{API_BASE}/channels/{channel_id}/messages"
        token = os.getenv('discordtoken') or input('Discord Token: ')
        bot=True
        headers={
            "Authorization": f"Bot {token}" if bot else token
        }
        r=[]
        for i in images:
            _r=requests.post(
                MESSAGE,
                headers=headers,
                files={i['name']:i['body']}
            )
            r.append({'name':i['name'], 'url':_r.json()['attachments'][0]['url']})
        #print(r)
        return r

    def createurl(images):
        imageurls=image.post(images)
        r=image.save(imageurls)
        return r
    
    def getimagefile(req):
        r=[]
        for i in req.files['image']:
            if i.name == '':
                return None
            r.append({'name':i.name, 'body':i.body})
        #print('image.getimage; r:', r)
        return r

    def getimage(imageid):
        return image.getall()[imageid]

    def save(images):
        _r={}
        r=image.getall()
        for i in images:
            _r.update({uuid():{'url':i['url'], 'name':i['name']}})
        r.update(_r)
        aes.writefile('.data/image', json.dumps(r, indent='\t', ensure_ascii=False))
        print('saved image!')
        return list(_r.keys())
            
class auth():

    def checkexists_id(userid):
        users=user.getall()
        if userid in users.keys():
            return True
        else:
            return False

    def check_password(userid, password):
        users=user.getall()
        if auth.checkexists_id(userid):
            return users[userid]['password'] == password
        else:
            return False
        
    def login(userid, password, sessionid):
        if auth.checkexists_id(userid):
            if auth.check_password(userid, password):
                expires.update({sessionid:userid})
                return True
            else:
                return 'パスワードが違います' #Invalid Password
        else:
            return 'IDが見つかりません' #Invalid ID

    def logout(req):
        sessionid=auth.getsessionid(req)
        if sessionid in expires.keys():
            del expires[sessionid]
            return True
        else:
            return False

    def register(userid, password, name):
        if userid.replace('_', '').isalnum():
            if not auth.checkexists_id(userid):
                users=user.getall_uuid()
                users.update(
                    {
                        uuid():{
                            'name':name,
                            'userid':userid,
                            'password':password,
                             'avatarurl':False,
                            'description':''
                        }
                    }
                )
                data=json.dumps(users, indent='\t', ensure_ascii=False)
                aes.writefile('.data/user', data)
                sendtodc(f'新規ユーザー {name} / {userid}')
                return True
            else:
                return 'このIDは既に存在します<br>別のIDを選択して下さい'
        else:
            return 'IDは英数字とアンダーバー(_)のみで設定して下さい'

    def create_sessionid(request, response):
        if request.cookies.get('X-SessionId', False):
            return False
        else:
            sessionid=''.join([random.choice(string.ascii_letters + string.digits) for i in range(64)])
            response.cookies['X-SessionId']=sessionid
            return sessionid

    def islogged(req):
        return req.cookies.get('X-SessionId', False) in expires.keys()

    def getuserid(req):
        return expires.get(req.cookies.get('X-SessionId', False), False)

    def getuseruuid(req):
        return user.getall().get(auth.getuserid(req), {}).get('useruuid', False)

    def getsessionid(request, response=None):
        if sessionid:=request.cookies.get('X-SessionId', False):
            return sessionid
        else:
            if response:
                return auth.create_sessionid(request, response)
            else:
                return False

key_size = 32
iv = '1234567890123456'.encode('utf-8')

class aes():

    def create_key(aeskey=None):

        p_key=aeskey or os.getenv('aeskey') or input('AES Key:')
        
        key_size_fill = p_key.zfill(key_size)
        key = key_size_fill[:key_size].encode('utf-8')
        return key


    def encrypt(data, aeskey=None):

        if type(data) != bytes:
            data=str(data).encode()

        key = aes.create_key(aeskey)
        obj = AES.new(key, AES.MODE_CFB, iv)

        ret_bytes = obj.encrypt(data)

        return ret_bytes


    def decrypt(data, aeskey=None):

        if type(data) != bytes:
            data=str(data).encode()

        key = aes.create_key(aeskey)
        obj = AES.new(key, AES.MODE_CFB, iv)
        return obj.decrypt(data)

    def readfile(filename):

        with open(filename, 'rb') as f:
            bf=f.read()
        r=aes.decrypt(bf).decode()
        return r

    def writefile(filename, data):

        d=aes.encrypt(data)
        with open(filename, 'wb') as f:
            f.write(d)
        return True
        
def uuid():
    return str(uuid4())

def sendtodc(message, channel_id=736391563319443567):
    API_BASE = "https://discordapp.com/api/v7"
    MESSAGE = f"{API_BASE}/channels/{{channel_id}}/messages"
    token = os.getenv('discordtoken') or input('Discord Token: ')
    bot = True  

    headers={
        "Authorization": f"Bot {token}" if bot else token
    }
    requests.post(
        MESSAGE.format(channel_id=channel_id),
        headers=headers,
        json={
           "content": f'`{message}`'
        }
    )

@app.listener('before_server_start')
def initapp(app, loop):
    app.aiohttp_session = aiohttp.ClientSession(loop=loop)

@app.route('/')
async def root(req):
    #print(req.remote_addr or req.ip)
    #print('req.cookies:', req.cookies)
    #print('logged:', req.cookies.get('X-SessionId', False) in expires.keys())
    #return res.text(':>')
    return render_html('root.html', logged=auth.islogged(req), userid=auth.getuserid(req), users=user.getall())
    
@app.route('/css')
async def sanic_css(req):
    cssname=req.args.get('file', 'None')
    if not os.path.isfile(f'./css/{cssname}'):return abort(404)
    return await res.file(f'./css/{cssname}')

@app.route('/js')
async def sanic_js(req):
    jsname=req.args.get('file', 'None')
    if not os.path.isfile(f'./js/{jsname}'):return abort(404)
    return await res.file(f'./js/{jsname}')

#login system
    
@app.get('/login')
async def sanic_get_login(req):
    if auth.islogged(req):
        return res.redirect('/')
    else:
        return render_html('login.html')

@app.post('/login')
async def sanic_post_login(req):
    if auth.islogged(req):
        return res.redirect('/')
    else:
        response=res.redirect('/')
        userid=req.form.get('userid', False)
        password=req.form.get('password', False)
        sessionid=auth.getsessionid(req, response)
        if userid:
            if password:
                if (message:=auth.login(userid, password, sessionid)) == True:
                    #response.cookies['logged']='True'
                    #response.cookies['userid']=userid
                    #response.cookies.update(
                    #    {
                    #        'logged':True,
                    #        'userid':userid
                    #    }
                    #)
                    return response
                else:
                    return render_html('login.html', message=message)
            else:
                return render_html('login.html', message='パスワードを入力して下さい')
        else:
            return render_html('login.html', message='ユーザーIDを入力して下さい')

@app.route('/logout')
async def sanic_logout(req):
    response=res.redirect('/')
    auth.logout(req)
    return response

@app.get('/register')
async def sanic_get_register(req):
    if auth.islogged(req):
        return res.redirect('/')
    else:
        return render_html('register.html')

@app.post('/register')
async def sanic_post_register(req):
    if auth.islogged(req):
        return res.redirect('/')
    else:
        response=res.redirect('/')
        name=req.form.get('name', False)
        userid=req.form.get('userid', False)
        password=req.form.get('password', False)
        password_confirm=req.form.get('password_confirm', False)        
        sessionid=auth.getsessionid(req, response)
        if name:
            if userid:
                if password:
                    if password == password_confirm:
                        if (message:=auth.register(userid, password, name)) == True:
                            auth.login(userid, password, sessionid)
                            return res.redirect('/')
                        else:
                            return render_html('register.html', message=message)
                    else:
                        return render_html('register.html', message='パスワード確認が違います')
                else:
                    return render_html('register.html', message='パスワードを入力して下さい')
            return render_html('register.html', message='ユーザーIDを入力して下さい')
        return render_html('register.html', message='名前を入力して下さい')
    
#thread

@app.route('/thread')
async def sanic_thread(req):
    return render_html('thread.html', threads=thread.getall())

@app.route('/thread/view')
async def sanic_thread_view(req):
    try:
        #print('req.args:', req.args)
        #print('404:', not 'id' in req.args.keys())
        #print('id:', req.args.get('id', [False]))
        if not (threadid:=req.args.get('id', False)):return abort(404)
        #print('Response!')
        return render_html('threadview.html', thread=thread.getthread(str(threadid)), users=user.getall_uuid(), logged=auth.islogged(req), enumerate=enumerate, images=image.getall(), admin=user.isadmin(auth.getuserid(req)))
    except KeyError:
        #print('KeyError!')
        return abort(404)

@app.post('/thread/post')
async def sanic_thread_post(req):
    if not auth.islogged(req):
        return res.redirect('/login')
    else:
        if not req.args.get('id', False):return abort(404)
        threadid=req.args['id'][0]
        useruuid=auth.getuseruuid(req)
        content=req.form.get('content', '')
        images=image.getimagefile(req)
        #with open(f'test/image/{image.name}', 'wb') as f:
        #    f.write(image.body)
        #with open('test/r.txt', 'w') as f:
        #    f.write(str(dict(req.files)))
        thread.post(threadid, useruuid, content, images)
        return res.redirect(f'/thread/view?id={threadid}')

@app.get('/thread/create')
async def sanic_thread_get_create(req):
    if not auth.islogged(req):
        return res.redirect('/login')
    else:
        return render_html('threadcreate.html')

@app.post('/thread/create')
async def sanic_thread_post_create(req):
    if not auth.islogged(req):
        return res.redirect('/login')
    else:
        print(req.form)
        name=req.form.get('title', False)
        content=req.form.get('content', False)
        images=image.getimagefile(req)
        if not name or not content:
            return render_html('threadcreate.html', message='タイトルまたは内容を空白にしてスレッドを作ることは出来ません')
        else:
            useruuid=auth.getuseruuid(req)
            r=thread.create(useruuid, name, content, images)
            return res.redirect(f'/thread/view?id={r}')

@app.post('/thread/delete')
async def sanic_thread_post_delete(req):
    if not auth.islogged(req):
        return res.redirect('/login')
    else:
        if user.isadmin(auth.getuserid(req)):
            if (threadid:=req.args.get('id', False)):
                if thread.delete(threadid):
                    return res.redirect('/thread')
                else:
                    return abort(404)
            else:
                return abort(400)
        else:
            return abort(403)
            
@app.websocket('/ws/thread')
async def sanic_ws_thread(req, ws):
	print('WS  Connected')
	#while True:
	#	try:
	#		data = json.loads(await ws.recv())
	#		print('WebSocket thread Received:', data, '\ntype:', type(data))
	#		rtype=data['type']
	#		if rtype == 'count':
	#			await ws.send(json.dumps({**data, 'result':len(thread.getthread(data['threadid'])['messages'])}))
	#		elif rtype == 'message':
	#			await ws.send(json.dumps({**data, 'result':thread.getthread(data['threadid'])['messages']}))
	#		elif rtype == 'users':
	#			users=user.getall_uuid();_t=thread.getthread(data['threadid']);_l=list(set([_k['authoruuid'] for _k in _t['messages']]));await ws.send(json.dumps({**data, 'result':{i:users[i]['name'] for i in users.keys() if i in _l}}))
	#		else:
	#			await ws.send('404')
	#	except KeyError:
	#		await ws.send('400')
	#		print(__import__('traceback').format_exc())
	#	except json.JSONDecodeError:
	#		await ws.send('400')
	#		print(__import__('traceback').format_exc())
	#	except ConnectionClosed:
	#		print('WS Disconnected')
	#else:
	#	print('WS Disconnected')

	threadid=req.args['id'][0]
	_old=thread.getthread(threadid)['messages']
	while True:
		_new=thread.getthread(threadid)['messages']
		if not _old == _new:
			users=user.getall_uuid();await ws.send(json.dumps([{**i, 'username':users[i['authoruuid']]['name'], 'userid':users[i['authoruuid']]['userid']} for i in [_i for _i in _new if not _i in _old]]))
		_old=_new
		await sleep(1)
	    
@app.route('/ws')
async def sanic_ws_test(req):
	return await res.file('html/wstest.html')
	
@app.get('/userinfo')
async def sanic_user_get_info(req):
    if auth.islogged(req):
        if (userid:=req.args.get('id', False)):
            if (userdata:=user.getall().get(userid, False)):
                return render_html('userinfo.html', myself=(userid == auth.getuserid(req)), userinfo=userdata, userid=userid)
            else:
                return abort(404)
        else:
            return render_html('userinfo.html', myself=True, userinfo=user.getuser(auth.getuserid(req)), userid=auth.getuserid(req)) #req user info
    else:
        if (userid:=req.args.get('id', False)):
            if (userdata:=user.getall().get(userid, False)):
                return render_html('userinfo.html', myself=False, userinfo=userdata, userid=userid)
            else:
                return abort(404)
        else:
            return abort(403)

@app.post('/userinfo')
async def sanic_user_post_info(req):
    #print(req.form)
    #return res.text('test')
    if not auth.islogged(req):
        return res.redirect('/login')
    else:
        if auth.getuserid(req) == req.args.get('id', False) or not 'id' in req.args.keys():
            userid=auth.getuserid(req)
            if (newname:=req.form.get('name', False)):
                user.change(userid, 'name', newname)
            if (newid:=req.form.get('id', False)):
                if newid in user.getall().keys():
                    return render_html('userinfo.html', myself=True, userinfo=user.getuser(userid), userid=userid, message='<font color="#ff0033">このIDは既に存在します</font>')
                user.change(userid, 'id', newid)
                expires[auth.getsessionid(req)]=newid
                userid=newid
            if (newpassword:=req.form.get('password', False)):
                user.change(userid, 'password', newpassword)
            return render_html('userinfo.html', myself=True, userinfo=user.getuser(userid), userid=userid, message='<font color="#00ff00">変更を保存しました</font>')
        else:
            return abort(403)
    
        
@app.route('/image_<name>')
async def sanic_image(req, name):
    if not (imageid:=req.args.get('id', False)):return abort(404)
    r=image.getimage(imageid)
    async def streaming_fn(resp):
        async with app.aiohttp_session.get(r['url']) as response:
            await resp.write(await response.read())

    return res.stream(streaming_fn, content_type='image/*')

@app.route('/getimage')
async def sanic_image(req):
	imageid=req.args.get('id', False);return res.redirect(f'/image_{image.getimage(imageid)["name"]}?id={imageid}')

@app.route('/update')
async def sanic_update(req):
	with open('update.json', 'r') as f:
		ul=json.load(f)
	return render_html('update.html', ul=ul)

@app.route('/cat')
async def sanic_cat(req):
    return await res.file('html/cat.html')

@app.route('/sans')
async def sanic_sans(req):
    return await res.file('html/sans.html')

@app.route('/r.txt')
async def sanic_r(req):
    return await res.file('test/r.txt')

@app.route('/execute_read')
async def sanic_execute_read(req):
	if not auth.islogged(req) or not user.isadmin(auth.getuserid(req)):
        return res.redirect('/')
    os.system('python3 testread.py')
    return res.text('200')

@app.route('/execute_write')
async def sanic_execute_write(req):
	if not auth.islogged(req) or not user.isadmin(auth.getuserid(req)):
        return res.redirect('/')
    os.system('python3 testwrite.py')
    return res.text('200')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)