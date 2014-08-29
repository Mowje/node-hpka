/*
* This is a script testing different methods of the hpka module
*
*
*
*/

var http = require('http');
var fs = require('fs');
var assert = require('assert');
var hpka = require('./hpka');
var cryptopp, sodium;

var algosToTest = hpka.supportedAlgorithms();
console.log('Supported algorithms: ' + JSON.stringify(algosToTest));
if (algosToTest.length == 0){
	console.log('Nothing to be tested, since nor cryptopp or sodium are installed');
	process.exit(1);
}

var useKeyRing = process.argv.length > 2 && process.argv[2] == 'keyring';

if (useKeyRing){
	console.log('Using KeyRings on clients instanciation');
	//Load the crypto modules so we have access to the KeyRings constructors
	try {
		cryptopp = require('cryptopp');
	} catch (e){

	}
	try {
		sodium = require('sodium');
	} catch (e){

	}
}

var userList = {};
var testUsername = 'test';
var testPassword = 'password';

var testKeyType = 'rsa';
var testKeyOptions = {
	ed25519: undefined,
	ecdsa: 'secp256k1',
	dsa: 2048,
	rsa: 2048
};

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
		//console.log('Common type : ecdsa');
		if (pubKey1.curveName != pubKey2.curveName) return false;
		if (pubKey1.point.x != pubKey2.point.x) return false;
		if (pubKey1.point.y != pubKey2.point.y) return false;
	} else if (pubKey1.keyType == "rsa"){
		//console.log('Common type : rsa');
		if (pubKey1.modulus != pubKey2.modulus) return false;
		if (pubKey1.publicExponent != pubKey2.publicExponent) return false;
	} else if (pubKey1.keyType == "dsa"){
		//console.log('Common type : dsa');
		if (pubKey1.primeField != pubKey2.primeField) return false;
		if (pubKey1.divider != pubKey2.divider) return false;
		if (pubKey1.base != pubKey2.base) return false;
		if (pubKey1.publicElement != pubKey2.publicElement) return false;
	} else if (pubKey1.keyType == 'ed25519'){
		//console.log('Common type : ed25519');
		if (pubKey1.publicKey != pubKey2.publicKey) return false;
	} else throw new TypeError('Invalid keyType');
	return true;
}

var requestHandler = function(req, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	if (req.username){
		//console.log(req.method + ' ' + req.url + ' authenticated request by ' + req.username);
		body = 'Authenticated as : ' + req.username;
	} else {
		//console.log(req.method + ' ' + req.url + ' anonymous request');
		body = 'Anonymous user';
	}
	headers['Content-Length'] = body.length;
	res.writeHead(200, headers);
	res.write(body);
	res.end();
};

var loginCheck = function(HPKAReq, req, res, callback){
	if (userList[HPKAReq.username] && typeof userList[HPKAReq.username] == 'object' && checkPubKeyObjects(getPubKeyObject(HPKAReq), userList[HPKAReq.username])) callback(true);
	else callback(false);
};

var registration = function(HPKAReq, req, res){
	var username = HPKAReq.username;
	var keyInfo = getPubKeyObject(HPKAReq);
	userList[username] = keyInfo;
	var body = 'Welcome ' + username + ' !';
	res.writeHead(200, {'Content-Type': 'text/plain', 'Content-Length': body.length});
	res.write(body);
	res.end();
};

var deletion = function(HPKAReq, req, res){
	if (typeof userList[HPKAReq.username] != 'object') return;
	userList[HPKAReq.username] = undefined;
	var headers = {'Content-Type': 'text/plain'};
	var body = HPKAReq.username + ' has been deleted!';
	headers['Content-Length'] = body.length;
	res.writeHead(200, headers);
	res.write(body);
	res.end();

};

var keyRotation = function(HPKAReq, newKeyReq, req, res){
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

//console.log('Starting the server');
var server = http.createServer(hpka.httpMiddleware(requestHandler, loginCheck, registration, deletion, keyRotation, true));
server.listen(2500, function(){
	//console.log('Server started');
});

function testStuff(callback){
	if (callback && typeof callback != 'function') throw new TypeError('When callback is defined, it must be a function');
	var keyPath = './hpkaclient.key';
	var newKeyPath = './newhpkaclient.key';
	var keyRing;
	var keyRing2;

	if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
	if (fs.existsSync(newKeyPath)) fs.unlinkSync(newKeyPath);

	//console.log('Looking for a client key');
	if (!fs.existsSync(keyPath)){
		//console.log('Creating a client key');
		keyRing = hpka.createClientKey(testKeyType, testKeyOptions[testKeyType], keyPath, (testKeyType == 'ed25519' ? testPassword : undefined));
		//console.log('Generated key pair : ' + JSON.stringify(keyRing.publicKeyInfo()));
	}

	if (!fs.existsSync(newKeyPath)){
		//console.log('Creating second client key');
		keyRing2 = hpka.createClientKey(testKeyType, testKeyOptions[testKeyType], newKeyPath, (testKeyType == 'ed25519' ? testPassword : undefined));
		//console.log('Second generated key pair : ' + JSON.stringify(keyRing2.publicKeyInfo()));
	}

	var reqOptions = {
		hostname: 'localhost',
		port: 2500,
		path: '/',
		method: 'GET'
	};

	//Sorry for the callback hell. :/ I just wanted to finish that stuff so I can code some "more interesting stuff" than a testing script.
	var client;
	if (useKeyRing){
		var kr;
		if (testKeyType == 'ed25519'){
			kr = new sodium.KeyRing();
			kr.load(keyPath, undefined, testPassword);
		} else {
			kr = new cryptopp.KeyRing();
			kr.load(keyPath);
		}
		client = new hpka.client(kr, testUsername);
	} else {
		client = new hpka.client(keyPath, testUsername, (testKeyType == 'ed25519' ? testPassword : undefined));
	}
	//First making an unauthenticated request
	var unauthReq = http.request(reqOptions, function(res){
		assert.equal(res.statusCode, 200, 'On successful anonymous requests, status code must be 200');
		res.on('data', function(data){
			assert.equal(data, 'Anonymous user', 'Unexpected string from server : ' + data);
			//Signing up
			client.registerUser(reqOptions, function(res){
				assert.equal(res.statusCode, 200, 'On successful registration, status code must be 200');
				res.on('data', function(data){
					assert.equal(data, 'Welcome ' + testUsername + ' !', 'Unexpected message on registration : ' + data);
					//Autheticated HTTP request
					client.request(reqOptions, undefined, function(res2){
						assert.equal(res2.statusCode, 200, 'Successful autheticated request must have status code 200');
						res2.on('data', function(data){
							assert.equal(data, 'Authenticated as : ' + testUsername, 'Unexpected message on authenticated request : ' + data);
							//Rotating keys
							client.rotateKeys(reqOptions, newKeyPath, function(res3){
								assert.equal(res3.statusCode, 200, 'Successful key rotation must have status code 200');
								res3.on('data', function(data){
									assert.equal(data, 'Keys have been rotated!', 'Unexpected message on key rotation : ' + data);
									//Checking that the key rotation was done properly by sending an authenticated request using the new key
									client.request(reqOptions, undefined, function(res4){
										assert.equal(res4.statusCode, 200, 'Successful authenticated request have status code 200');
										res4.on('data', function(data){
											assert.equal(data, 'Authenticated as : ' + testUsername, 'Unexpected message on authenticated request : ' + data);
											//Deleting user
											client.deleteUser(reqOptions, function(res5){
												assert.equal(res5.statusCode, 200, 'Successful account deletion must have status code 200');
												res5.on('data', function(data){
													assert.equal(data, testUsername + ' has been deleted!', 'Unexpected deletion message : ' + data);
													//Trying to do an authenticated request in order to trigger an error (since the user has just been deleted)
													client.request(reqOptions, undefined, function(res6){
														assert.equal(res6.statusCode, 445, 'Status code must be 445, but it\'s ' + res6.statusCode + ' instead');
														res6.on('data', function(data){
															assert.equal(data, 'Invalid key or unregistered user', 'The user didn\'t seem to be deleted, even a HPKA delete request was sent');
															//console.log('Received data from server (auth request after user deletion) : ' + data);
															if (callback) callback();
														});
													});
												});
											});
										});
									});
								});
							}, testPassword); //Passing the keyFile password into the rotateKeys method
						});
					})
				});
			});
		});
	});
	unauthReq.end(); //Yes, unlike HPKA requests, standard HTTP requests must be `end()`-ed... Sorry if automaitcally `end()`-ing HPKA requests causes you some trouble
}


var keyIndex = 0;
testKeyType = algosToTest[0].toLowerCase();
var testAlgos = function(callback){
	if (callback && typeof callback !== 'function') throw new TypeError('When defined, callback must be a function');
	console.log('Testing ' + testKeyType);
	testStuff(function(){
		console.log(testKeyType + ' has been tested successfully');
		keyIndex++;
		if (keyIndex == algosToTest.length) process.exit(0);
		testKeyType = algosToTest[keyIndex].toLowerCase();
		testAlgos(testAlgos);
	});
};
testAlgos();
