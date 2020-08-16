window.onload = function() {

	var el1=document.getElementById('messageform')
	if (el1) el1.action=location.href.replace('view', 'post')

	var el2=document.getElementById('deleteform')
	if (el2) el2.action=location.href.replace('view', 'delete')

	var wsurl=`wss://${location.hostname}/ws/thread${location.search}`
	var socket = new WebSocket(wsurl);

	socket.addEventListener('message', function(e) {
		console.log(`< ${e.data}`)
		var msgs = JSON.parse(e.data)
		var msg
		var mi
		var imgs
		for (var i = 0;i < msgs.length;i++) {
			msg = msgs[i]
			mi = document.getElementById('messages').childElementCount
			imgs = ''
			if (msg['image']) {
				for (var i2 = 0;i2 < msg.image.length;i2++) {
					imgs+=`<img src="/getimage?id=${msg['image'][i2]['id']}"><br>`
				}
			}
			document.getElementById('messages').innerHTML+=`
				<div id="msg_${mi}">
					<p id="msg_${mi}">${mi} : 
						<a style="text-decoration: none;" href="/userinfo?id=${msg['userid']}">
							<font color="#fff">${msg['username']}</font>
						</a>
						<font color="#808080">- ${msg['time']}</font>
					</p>
					<div class="div-pre">${msg['content']}</div>
					<br>
					${imgs ? imgs : ''}
				</div>
				`
		}
		console.log('Updated')
	});

	socket.addEventListener('close', function(e) {
		socket = new WebSocket(`wss://${location.hostname}/ws/thread`);
	})
};