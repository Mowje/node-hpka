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

var testKeyType = 'ed25519';
var testKeyOptions = 'secp256r1';

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
	} else if (HPKAReq.keyType == 'ed25519'){
		if (!(HPKAReq.publicKey)) throw new TypeError('Malformed Ed25519 request');
		reqObj.publicKey = HPKAReq.publicKey;
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
	} else if (pubKey1.keyType == 'ed25519'){
		console.log('Common type : ed25519');
		if (pubKey1.publicKey != pubKey2.publicKey) return false;
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
	if (userList[HPKAReq.username] && typeof userList[HPKAReq.username] == 'object' && checkPubKeyObjects(getPubKeyObject(HPKAReq), userList[HPKAReq.username])) callback(true);
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
	userList[HPKAReq.username] = undefined;
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
		if (checkPubKeyObjects(userList[HPKAReq.username], getPubKeyObject(HPKAReq))){
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
var newKeyPath = './newhpkaclient.key';
var keyRing;
var keyRing2;

if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
if (fs.existsSync(newKeyPath)) fs.unlinkSync(newKeyPath);

console.log('Looking for a client key');
if (!fs.existsSync(keyPath)){
	console.log('Creating a client key');
	keyRing = hpka.createClientKey(testKeyType, testKeyOptions, keyPath);
	console.log('Generated key pair : ' + JSON.stringify(keyRing.publicKeyInfo()));
}

if (!fs.existsSync(newKeyPath)){
	console.log('Creating second client key');
	keyRing2 = hpka.createClientKey(testKeyType, testKeyOptions, newKeyPath);
	console.log('Second generated key pair : ' + JSON.stringify(keyRing2.publicKeyInfo()));
}

var reqOptions = {
	hostname: 'localhost',
	port: 2500,
	path: '/',
	method: 'GET'
};

//Sorry for the callback hell. :/ I just wanted to finish that stuff so I can code some "more interesting stuff" than a testing script.
console.log('Creating a client instance and loading the key');
var client = new hpka.client(keyPath, 'test');
//First making an unauthenticated request
var unauthReq = http.request(reqOptions, function(res){
	res.on('data', function(data){
		console.log('Data recieved from server (unauthenticated req) : ' + data);
		//Signing up
		client.registerUser(reqOptions, function(res){
			res.on('data', function(data){
				console.log('Received data from server (on registration) : ' + data);
				//Autheticated HTTP request
				client.request(reqOptions, undefined, function(res2){
					res2.on('data', function(data){
						console.log('Received data from server (on auth request) : ' + data);
						//Rotating keys
						client.rotateKeys(reqOptions, newKeyPath, function(res3){
							res3.on('data', function(data){
								console.log('Received data from server (on key rotation) : ' + data);
								//Checking that the key rotation was done properly by sending an authenticated request using the new key
								client.request(reqOptions, undefined, function(res4){
									res4.on('data', function(data){
										console.log('Received data from server (on auth request after key rotation) : ' + data);
										//Deleting user
										client.deleteUser(reqOptions, function(res5){
											res5.on('data', function(data){
												console.log('Received data from server (on user deletion) : ' + data);
												//Trying to do an authenticated request in order to trigger an error (since the user has just been deleted)
												client.request(reqOptions, undefined, function(res6){
													res6.on('data', function(data){
														console.log('Received data from server (auth request after user deletion) : ' + data);
														process.exit();
													});
												});
											});
										});
									});
								});
							});
						});
					});
				})
			});
		});
	});
});
unauthReq.end(); //Yes, unlike HPKA requests, standard HTTP requests must be `end()`-ed... Sorry if automaitcally `end()`-ing HPKA requests causes you some trouble
