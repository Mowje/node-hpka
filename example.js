var http = require('http');
var fs = require('fs');
var hpka = require('./hpka');

var userList = {};

//Getting the PKA info from a HPKAReq object
function getPubKeyObject(HPKAReq){
	//Checking that HPKAReq object is correctly formed
	var reqObj = {};
	if (!HPKAReq.keyType) throw new TypeError('Invalid HPKAReq obejct on getPubKeyObject method');
	reqObj.keyType = HPKAReq.keyType;
	if (HPKAReq.keyType == 'ecdsa'){ //ECDSA case
		if (!(HPKAReq.curveName && HPKAReq.point && HPKAReq.point.x && HPKAReq.point.y)) throw new TypeError('Malformed ECDSA request');
		reqObj.curveName = HPKAReq.curveName;
		reqObj.point = HPKAReq.point;
	} else if (HPKAReq.keyType == 'rsa'){ //RSA case
		if (!(HPKAReq.modulus && HPKAReq.publicExponent)) throw new TypeError('Malformed RSA request');
		reqObj.modulus = HPKAReq.modulus;
		reqObj.publicExponent = HPKAReq.publicExponent;
	} else if (HPKAReq.keyType == 'dsa'){ //DSA case
		if (!(HPKAReq.primeField && HPKAReq.divider && HPKAReq.base && HPKAReq.publicElement)) throw new TypeError('Malformed DSA request');
		reqObj.primeField = HPKAReq.primeField;
		reqObj.divider = HPKAReq.divider;
		reqObj.base = HPKAReq.base;
		reqObj.publicElement = HPKAReq.publicElement;
	} else throw new TypeError('Invalid key type : ' + HPKAReq.keyType);
	return reqObj;
}

var requestHandler = function(req, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	if (req.username){
		console.log(req.method + ' ' + req.url + ' authenticated request by ' + req.username);
		body = 'Authenticated as : ' + req.username;
	} else {
		console.log(req.method + ' ' + req.url + ' anonymous request');
		body = 'Anonymous user';
	}
	headers['Content-Length'] = body.length;
	res.writeHead(200, headers);
	res.write(body);
	res.end();
};

var loginCheck = function(HPKAReq, res, callback){
	if (typeof userList[HPKAReq.username] == 'string' && getPubKeyObject(HPKAReq) == userList[HPKAReq.username]) callback(true);
	else callback(false);
};

var registration = function(HPKAReq, res){
	var username = HPKAReq.username;
	var keyInfo = getPubKeyObject(HPKAReq);
	userList[username] = keyInfo;
	var body = 'Welcome ' + username + ' !';
	res.writeHead(200, {'Content-Type': 'text/plain', 'Content-Length': body.length});
	res.write(body);
	res.end();
};

var server = http.createServer(hpka.httpMiddleware(requestHandler, loginCheck, registration, true));
server.listen(2500);

var keyPath = './hpkaclient.key';

if (!fs.existsSync(keyPath)){
	hpka.createClientKey(keyPath, 'ecdsa', 'secp256r1');
}

var reqOptions = {
	hostname: 'localhost',
	port: 2500,
	path: '/',
	method: 'GET'
};
var client = hpka.client(keyPath, 'test');
client.request(reqOptions, undefined, 1, function(res){
	res.on('data', function(data){
		console.log('Recieved data from server : ' + data);
	});
	res.on('close', function(){
		client.request(reqOptions, undefined, 0, function(res2){
			res2.on('data', function(data){
				console.log('Recieved data from server : ' + data);
			});
			res2.on('close', function(){
				console.log('End of example HPKA script');
				process.exit();
			});
		});
	});
});