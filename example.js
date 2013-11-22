/*
* This is a script testing different methods of the hpka module
*
*
*
*/

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

function checkPubKeyObjects(pubKey1, pubKey2){
	if (!(typeof pubKey1 == 'object' && typeof pubKey2 == 'object')) throw new TypeError('Parameters must be objects');
	if (pubKey1.keyType != pubKey2.keyType) return false;
	if (pubKey1.keyType == "ecdsa"){
		console.log('Common type : ecdsa');
		if (pubKey1.curveName != pubKey2.curveName) return false;
		if (pubKey1.point.x != pubKey2.point.x) return false;
		if (pubKey1.point.y != pubKey2.point.y) return false;
	} else if (pubKey1.keyType == "rsa"){
		console.log('Common type : rsa');
		if (pubKey1.modulus != pubKey2.modulus) return false;
		if (pubKey1.publicExponent != pubKey2.publicExponent) return false;
	} else if (pubKey1.keyType == "dsa"){
		console.log('Common type : dsa');
		if (pubKey1.primeField != pubKey2.primeField) return false;
		if (pubKey1.divider != pubKey2.divider) return false;
		if (pubKey1.base != pubKey2.base) return false;
		if (pubKey1.publicElement != pubKey2.publicElement) return false;
	} else throw new TypeError('Invalid keyType');
	return true;
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
	if (typeof userList[HPKAReq.username] == 'object' && checkPubKeyObjects(getPubKeyObject(HPKAReq), userList[HPKAReq.username])) callback(true);
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

var deletion = function(HPKAReq, res){
	if (typeof userList[HPKAReq.username] != 'object') return;
	userList[HPKAReq.username] = null;
	var headers = {'Content-Type': 'text/plain'};
	var body = HPKAReq.username + ' has been deleted!';
	headers['Content-Length'] = body.length;
	res.writeHead(200, headers);
	res.write(body);
	res.end();

};

var keyRotation = function(HPKAReq, newKeyReq, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	var errorCode;
	//Check that the username exists
	if (typeof userList[HPKAReq.username] != 'object'){
		body = 'Unregistered user';
		errorCode = 445;
		headers['HPKA-Error'] = 4;
	} else {
		//Check that the actual key is correct
		if (checkPubKeyObjects(userList[HPKAReq.username], getPubKeyObject(HPKAReq)){
			//Replace the actual ke by the new key
			userList[HPKAReq.username] = getPubKeyObject(newKeyReq);
			body = 'Keys have been rotated!';
		} else {
			body = 'Invalid public key'
			errorCode = 445;
			headers['HPKA-Error'] = 3;
		}
	}
	headers['Content-Length'] = body.length;
	res.writeHead(errorCode || 200, headers);
	res.write(body);
	res.end();
};

console.log('Starting the server');
var server = http.createServer(hpka.httpMiddleware(requestHandler, loginCheck, registration, deletion, keyRotation, true));
server.listen(2500, function(){
	console.log('Server started');
});

var keyPath = './hpkaclient.key';
var keyRing;

console.log('Looking for a client key');
if (!fs.existsSync(keyPath)){
	console.log('Creating a client key');
	keyRing = hpka.createClientKey('dsa', 2048, keyPath);
	console.log('Generated key pair : ' + JSON.stringify(keyRing.publicKeyInfo()));
}

var reqOptions = {
	hostname: 'localhost',
	port: 2500,
	path: '/',
	method: 'GET'
};

console.log('Creating a client instance and loading the key');
var client = new hpka.client(keyPath, 'test');
client.request(reqOptions, undefined, 1, function(res){
	res.on('data', function(data){
		console.log('Recieved data from server (on registration) : ' + data);
		client.request(reqOptions, undefined, 0, function(res2){
			res2.on('data', function(data){
				console.log('Recieved data from server (on auth request) : ' + data);
				process.exit();
			});
		})
	});
});