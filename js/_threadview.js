window.onload = function() {

	var el1=document.getElementById('messageform')
	if (el1) el1.action=location.href.replace('view', 'post')

	var el2=document.getElementById('deleteform')
	if (el2) el2.action=location.href.replace('view', 'delete')

	var socket = new WebSocket(`wss://${location.hostname}/ws/thread`);
	var threadid = location.search.split('=')[1]

	socket.addEventListener('message', function(e) {
		console.log(`< ${e.data}`)
	});

	socket.addEventListener('close', function(e) {
		socket = new WebSocket(`wss://${location.hostname}/ws/thread`);
	});

	function wssend() {
		socket.send(JSON.stringify({'type':'count', 'threadid':threadid}))
	}

	setInterval(wssend, 1000);

};