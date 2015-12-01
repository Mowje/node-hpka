var http = require('http');
var fs = require('fs');
var assert = require('assert');
var express = require('express');
var hpka = require('../hpka');
var cryptopp, sodium;
var Buffer = require('buffer').Buffer;

var server;
var hpkaMiddleware;
var serverPort = 2500;
var maxSessionLife = 7 * 24 * 3600; //One week validity

var applicationToUse;

var userList = {};
var sessions = {};

/*
* Useful function for the server
*/

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

function writeRes(res, body, headers, statusCode){
	headers = headers || {};
	var bodyLength;

	if (typeof body == 'object' && !Buffer.isBuffer(body)){
		body = JSON.stringify(body);
		headers['Content-Type'] = 'application/json';
	}
	if (Buffer.isBuffer(body)){
		bodyLength = Buffer.byteLength(body);
	} else { //Assuming string
		bodyLength = body.length;
	}

	headers['Content-Length'] = bodyLength;

	res.writeHead(statusCode || 200, headers);
	res.write(body);
	res.end();
}

function writeHpkaErr(res, message, errorCode){
	writeRes(res, message, {'HPKA-Error': errorCode}, 445);
}

/*
* Server handlers
*/

var requestHandler = function(req, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	if (req.username){
		//console.log(req.method + ' ' + req.url + ' authenticated request by ' + req.username);
		body = 'Authenticated as : ' + req.username;
		//Manual signature verification
		var hpkaReq = req.headers['hpka-req'];
		var hpkaSig = req.headers['hpka-signature'];
		var method = req.method;
		var reqUrl = 'http://' + (req.headers.hostname || req.headers.host) + req.url
		//console.log('HpkaReq: ' + hpkaReq + '; HpkaSig: ' + hpkaSig + '; ' + method + '; reqUrl: ' + reqUrl);
		hpka.verifySignature(hpkaReq, hpkaSig, reqUrl, method, function(err, isValid, username, hpkaReq){
			if (err) console.error('Error in hpkaReq: ' + err);
			if (!isValid) console.log('External validation failed');
			//else console.log('External validation success: ' + username + ': ' + JSON.stringify(hpkaReq));
		});
	} else {
		//console.log(req.method + ' ' + req.url + ' anonymous request');
		body = 'Anonymous user';
	}

	writeRes(res, body, headers, 200);
};

var postHandler = function(req, res){
	if (req.body && Object.keys(req.body).length > 0){
		//console.log('Testing req values');
		assert.equal(req.body['field-one'], 'test', 'Unexpected form content');
		assert.equal(req.body['field-two'], 'test 2', 'Unexpected form content');
		assert.equal(req.headers.test, '1', 'Unexpected value the "test" header');
	}
	//console.log('Received form data: ' + JSON.stringify(req.body));
	//console.log('"test" header value: ' + req.headers.test);
	if (req.username){
		res.send(200, 'OK');
	} else {
		res.send(401, 'Not authenticated');
	}
};

var loginCheck = function(HPKAReq, req, res, callback){
	if (userList[HPKAReq.username] && typeof userList[HPKAReq.username] == 'object' && checkPubKeyObjects(getPubKeyObject(HPKAReq), userList[HPKAReq.username])) callback(true);
	else callback(false);
};

var registration = function(HPKAReq, req, res){
	var username = HPKAReq.username;
	var keyInfo = getPubKeyObject(HPKAReq);
	userList[username] = keyInfo;
	writeRes(res, 'Welcome ' + username + ' !', {'Content-Type': 'text/plain'});
};

var deletion = function(HPKAReq, req, res){
	if (typeof userList[HPKAReq.username] != 'object') return;
	var keyInfo = getPubKeyObject(HPKAReq);
	if (!checkPubKeyObjects(keyInfo, userList[HPKAReq.username])){
		writeHpkaErr(res, 'Invalid public key', 3);
		return;
	}
	userList[HPKAReq.username] = undefined;
	writeRes(res, HPKAReq.username  + ' has been deleted!', {'Content-Type': 'text/plain'});
};

var keyRotation = function(HPKAReq, newKeyReq, req, res){
	var headers = {'Content-Type': 'text/plain'};
	var body;
	var statusCode;
	//Check that the username exists
	if (typeof userList[HPKAReq.username] != 'object'){
		writeHpkaErr(res, 'Unregistered user', 4);
	} else {
		//Check that the actual key is correct
		if (checkPubKeyObjects(userList[HPKAReq.username], getPubKeyObject(HPKAReq))){
			//Replace the actual ke by the new key
			userList[HPKAReq.username] = getPubKeyObject(newKeyReq);
			body = 'Keys have been rotated!';
		} else {
			body = 'Invalid public key'
			statusCode = 445;
			headers['HPKA-Error'] = 3;
		}
	}
	writeRes(res, body, {'Content-Type': 'text/plain'}, statusCode);
};

var sessionCheck = function(SessionReq, req, res, callback){
	var username = SessionReq.username;
	var sessionId = SessionReq.sessionId;

	if (!sessions[username]){
		callback(false);
		return;
	}

	var validId = false;
	for (var i = 0; i < sessions[username].length; i++){
		if (sessions[username][i]){
			validId = true;
			break;
		}
	}
	callback(validId);
};

var sessionAgreement = function(HPKAReq, req, callback){
	var username = HPKAReq.username;
	var sessionId = HPKAReq.sessionId;
	var keyInfo = getPubKeyObject(HPKAReq);
	//Expiration date agreement
	var finalSessionExpiration;
	var n = Math.floor(Date.now() / 1000);
	var currentMaxExpiration = n + maxSessionLife;
	//User-provided expiration date for the sessionId
	var userSetExpiration = HPKAReq.sessionExpiration || 0;
	if (userSetExpiration == 0 || userSetExpiration > currentMaxExpiration){ //Enforce lifespan
		finalSessionExpiration = currentMaxExpiration;
	} else {
		finalSessionExpiration = userSetExpiration;
	}
	//Check keys
	if (typeof keyInfo == 'object' && checkPubKeyObjects(keyInfo, userList[username])){
		//Accept sessionId
		if (sessions[username]){
			//Save the sessionId in the existing array
			//But before that, check that it's not already in the array
			var alreadyAgreed = false;
			for (var i = 0; i < sessions[username].length; i++) if (sessions[username][i] == sessionId) alreadyAgreed = true;
			if (!alreadyAgreed) sessions[username].push(sessionId);
		} else sessions[username] = [sessionId]; //Creating an array containing that new sessionId
		//Tell the middleware that the sessionId agreement is valid
		callback(true, finalSessionExpiration);
	} else callback(false);
};

var sessionRevocation = function(HPKAReq, req, callback){
	var username = HPKAReq.username;
	var sessionId = HPKAReq.sessionId;
	var keyInfo = getPubKeyObject(HPKAReq);
	//Checks keys
	if (typeof keyInfo == 'object' && checkPubKeyObjects(keyInfo, userList[username])){
		//Revoke sessionId
		var currentSessionList = sessions[username];
		if (currentSessionList){
			if (currentSessionList.length == 1) sessions[username] = null;
			else {
				//Check that the sessionId is in the array and remove it
				var sessionIdIndex = -1;
				for (var i = 0; i < currentSessionList.length; i++){
					if (currentSessionList[i] == sessionId){
						currentSessionList.splice(i, 1);
						break;
					}
				}
			}
		}
		callback(true);
	} else callback(false);
};

exports.setup = function(useInStrictMode, disallowSessions, useExpress){
	if (useExpress){
		if (!disallowSessions){
			hpkaMiddleware = hpka.expressMiddleware(loginCheck, registration, deletion, keyRotation, useInStrictMode, sessionCheck, sessionAgreement, sessionRevocation);
		} else {
			hpkaMiddleware = hpka.expressMiddleware(loginCheck, registration, deletion, keyRotation, useInStrictMode);
		}
		var app = express();
		app.use(express.bodyParser());
		app.use(hpkaMiddleware);

		app.get('/', requestHandler);
		app.post('/', postHandler);

		applicationToUse = app;
	} else {
		if (!disallowSessions){
			hpkaMiddleware = hpka.httpMiddleware(requestHandler, loginCheck, registration, deletion, keyRotation, useInStrictMode, sessionCheck, sessionAgreement, sessionRevocation);
		} else {
			hpkaMiddleware = hpka.httpMiddleware(requestHandler, loginCheck, registration, deletion, keyRotation, useInStrictMode);
		}
		applicationToUse = hpkaMiddleware;
	}
};

exports.clear = function(){
	userList = {};
	sessions = {};
};

exports.start = function(cb){
	if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');
	if (!hpkaMiddleware) this.setup();

	server = http.createServer(applicationToUse);
	server.listen(serverPort, function(){
		console.log('The test server has been started on port ' + serverPort);
		if (cb) cb();
	});
};

exports.stop = function(cb){
	if (cb && typeof cb != 'function') throw new TypeError('when defined, cb must be a function');

	server.close(function(){
		console.log('The test server has been closed');
		server = undefined;
		if (cb) cb();
	});
};

exports.getServerPort = function(){
	return serverPort;
};

exports.setServerPort = function(p){
	if (typeof p != 'number') throw new TypeError('p must be a number');
	if (!(p == Math.floor(p))) throw new TypeError('p must be an integer number');
	if (!(p > 0 && p <= 65535)) throw new TypeError('p must be in the range [1..65535]');

	serverPort = p;
};
