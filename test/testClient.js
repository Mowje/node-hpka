var http = require('http');
var fs = require('fs');
var assert = require('assert');
var hpka = require('../hpka');
var crypto = require('crypto');
var cryptopp, sodium;
var Buffer = require('buffer').Buffer;
var FormData = require('form-data');

//The test user's name and password/passphrase
//Note : the password is only used with Ed25519 because its keyring allows it
//The keyring from node-cryptopp doesn't support yet password protection for key files
var testUsername = 'test';
var testPassword = 'password';
var testSessionId;
var keyType;

var testClient;

var serverSettings;

//The options for each keyType test
var testKeyOptions = {
	ed25519: undefined,
	ecdsa: 'secp256k1',
	dsa: 2048,
	rsa: 2048
};

var keyPath = './hpkaclient.key';
var newKeyPath = './newhpkaclient.key';

//Callback(err, body, res)
function performReq(reqOptions, body, callback){
	if (typeof reqOptions != 'object') throw new TypeError('reqOptions must be an object');
	if (body && (Buffer.isBuffer(body) || typeof body == 'string' || typeof body == 'object')) throw new TypeError('when defined, body must either be a buffer or a string');
	if (typeof callback != 'function') throw new TypeError('callback must be a function');

	if (body){
		if (!reqOptions.headers) reqOptions.headers = {};

		//Object to JSON
		if (typeof body == 'object' && !(Buffer.isBuffer(body) || body instanceof FormData)){
			body = JSON.stringify(body);
			reqOptions.headers['Content-Type'] = 'application/json';
		}
		//Calc body length
		if (Buffer.isBuffer(body)){
			reqOptions.headers['Content-Length'] = Buffer.byteLength(body);
		} else if (typeof body == 'string'){
			reqOptions.headers['Content-Length'] = body.length;
		} else if (body instanceof FormData){
			var initialHeaders = options.headers;
			options.headers = body.getHeaders();
			for (initialHeaderName in initialHeaders){
				options.headers[initialHeaderName] = initialHeaders[initialHeaderName];
			}
		}
	}

	var req = http.request(reqOptions, function(res){
		processRes(res, function(resBody){
			callback(undefined, resBody, res);
		});
	});

	req.on('error', callback);

	if (body){
		if (body instanceof FormData) body.pipe(req);
		else {
			req.write(body);
			req.end();
		}
	} else req.end();
}

function processRes(res, cb){
	var b = '';
	res.setEncoding('utf8');
	res.on('end', function(){cb(b)});
	res.on('data', function(part){b += part});
}

function validStatusCode(n){
	if (!n) return;
	var v = typeof n == 'number' && Math.floor(n) == n && n >= 100 && n < 600;
	if (!v) throw new TypeError('when defined, _expectedStatusCode must be an integer number, with the [100..600[ range');
}

function validHPKAErrorCode(n){
	if (!n) return;
	var nCopy = n;
	if (typeof v == 'string') n = parseInt(n);
	if (isNaN(n)) throw new TypeError('Invalid number : ' + nCopy);
	var v = typeof n == 'number' && Math.floor(n) == n && n > 0 && n <= 16;
	if (!v) throw new TypeError('Invalid error code : ' + nCopy);
}

function isString(s){
	return typeof s == 'string' && s.length > 0;
}

function isFunction(f){
	return typeof f == 'function';
}

exports.setKeyType = function(_keyType){
	if (typeof _keyType != 'string') throw new TypeError('_keyType must be a string');

	if (!(_keyType == 'rsa' || _keyType == 'ecdsa' || _keyType == 'dsa' || _keyType == 'ed25519')) throw new TypeError('_keyType must either be rsa, ecdsa, dsa or ed25519');
	var availKeyType = false;
	var supportedAlgorithms = hpka.supportedAlgorithms();
	for (var i = 0; i < supportedAlgorithms.length; i++){
		if (supportedAlgorithms[i] == _keyType){
			availKeyType = true;
			break;
		}
	}

	if (!availKeyType) throw new Error(_keyType + ' is not supported (sodium ro cryptopp is missing)');

	keyType = _keyType;
};

exports.setServerSettings = function(_serverSettings){
	if (typeof _serverSettings != 'object') throw new TypeError('_serverSettings must be an object');

	serverSettings = _serverSettings;
};

exports.setup = function(keyPath, altKeyPath, allowGetSessions){
	hpka.createClientKey(keyType, testKeyOptions[keyType], keyPath, password);
	if (altKeyPath) hpka.createClientKey(keyPath, testKeyOptions[keyType], altKeyPath, password);

	testClient = new hpka.client(keyPath, testUsername, keyType == 'ed25519' ? password : undefined, allowGetSessions);
};

//Write the different test cases that must be executed for each key type. Will be called from index.js
exports.unauthenticatedReq = function(cb){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	performReq(serverSettings, function(err, body, res){
		if (err) throw err;
		assert.equal(res.statusCode, 200, 'On successful anonymous requests, status code must be 200');
		assert.equal(body, 'Anonymous user', 'Unexpected string from server: ' + data);
		cb();
	});
};

exports.registrationReq = function(cb, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || ('Welcome ' + testUsername + ' !');
	var expectedStatusCode = _expectedStatusCode || 200;

	testClient.registerUser(serverSettings, function(res){
		processRes(res, function(body){
			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on registration: ' + res.statusCode);
			assert.equal(body, expectedBody, 'Unexpected message on registration: ' + body);
			cb();
		});
	}, function(err){throw err;});
};

exports.authenticatedReq = function(cb, withForm, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || ('Authenticated as : ' + testUsername);
	var expectedStatusCode = _expectedStatusCode || 200;

	testClient.request(serverSettings, undefined, function(res){
		processRes(res, function(body){
			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code: ' + res.statusCode);
			assert.equal(body, expectedBody, 'Unexpected body: ' + body);
			cb();
		});
	}, function(err){throw err;});
};

exports.deletionReq = function(cb, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || (testUsername + ' has been deleted!');
	var expectedStatusCode = _expectedStatusCode || 200;

	testClient.deleteUser(serverSettings, function(res){
		processRes(res, function(body){
			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on user deletion: ' + res.statusCode);
			assert.equal(body, expectedBody, 'Unexpected response body: ' + body);
			cb();
		});
	}, function(err){throw err;});
};

exports.keyRotationReq = function(cb, newKeyPath, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (!newKeyPath) throw new TypeError('newKeyPath must be provided');

	var fullKeyPath = path.join(process.cwd(), newKeyPath);
	if (!fs.existsSync(fullKeyPath)) throw new Error('newKey cannot be found');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || ('Keys have been rotated!');
	var expectedStatusCode = _expectedStatusCode || 200;

	testClient.rotateKeys(serverSettings, fullKeyPath, function(res){
		processRes(res, function(body){
			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on key rotation: ' + res.statusCode);
			assert.equal(body, expectedBody, 'Unexpected response body on key rotation: ' + body);

			//Rotating key paths as well, once keys have been rotated on the server
			var tempKeyPath = keyPath;
			keyPath = newKeyPath;
			newKeyPath = tempKeyPath;

			cb();
		});
	}, function(err){throw err;});

};

/*
* HPKA authenticated request with spoofed signature
* Expected body, status code and HPKA error code can be changed
* HPKA error code check can be dismissed by setting _expectedHPKAError = null
*/
exports.spoofedSignatureReq = function(cb, _expectedBody, _expectedStatusCode, _expectedHPKAError){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);
	validHPKAErrorCode(_expectedHPKAError);

	var kr; //The keyring of the current user
	var fullKeyPath = path.join(process.cwd(), keyPath);
	if (keyType == 'ed25519'){
		kr = new (require('sodium').KeyRing)();
		kr.load(keyPath, testPassword);
	} else {
		kr = new (require('cryptopp').KeyRing)();
		kr.load(keyPath);
	}

	var expectedBody = 'Invalid signature.' || _expectedBody;
	var expectedStatusCode = 445 || _expectedStatusCode;
	var expectedHPKAErrValue = _expectedHPKAError == null ? null : ((_expectedHPKAError && _expectedHPKAError.toString()) || '2');

	var hostAndPath = serverSettings.hostname + serverSettings.path;

	hpka.buildPayload(kr, testUsername, 0x00, hostAndPath, serverSettings.method, function(reqStr, sigStr){
		var reqOptions = {
			host: serverSettings.host,
			path: serverSettings.path,
			method: serverSettings.method,
			port: serverSettings.port,
			headers: {
				'HPKA-Req': reqStr,
				'HPKA-Signature': crypto.randomBytes(32).toString('base64')
			}
		};

		performReq(reqOptions, undefined, function(err, body, res){
			if (err) throw err;

			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code for request with spoofed signature: ' + res.statusCode);
			assert.equal(body, expectedBody, 'Unexpected response for request with spoofed signature: ' + body);
			if (expectedHPKAErrValue) assert.equal(res.headers['hpka-error'], expectedHPKAErrValue, 'Unexpected HPKA error code: ' + expectedHPKAErrValue);

			cb();
		});
	});
};

exports.spoofedHostReq = function(cb, _exp){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	var kr; //The keyring of the current user
	var fullKeyPath = path.join(process.cwd(), keyPath);
	if (keyType == 'ed25519'){
		kr = new (require('sodium').KeyRing)();
		kr.load(keyPath, testPassword);
	} else {
		kr = new (require('cryptopp').KeyRing)();
		kr.load(keyPath);
	}

	hpka.buildPayload(kr, testUsername, 0x00, 'badservernameandpath', serverSettings.method, function(reqStr, sigStr){

	});
}

exports.spoofedUsernameReq = function(withUsername, cb){
	if (typeof withUsername != 'string') throw new TypeError('withUsername must be a string');
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

};

exports.spoofedSessionReq = function(withUsername, cb){
	if (typeof withUsername != 'string') throw new TypeError('withUsername must be a string');
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

};

exports.malformedReq = function(cb, _expectedBody, _expectedStatusCode, _expectedHPKAError){

};

exports.sessionAgreementReq = function(cb, wantedSessionExpiration, _expectedBody, _expectedStatusCode, _expectedSessionExpiration){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || ('Session created');
	var expectedStatusCode = _expectedStatusCode || 200;
	var expectedSessionExpiration = _expectedSessionExpiration || wantedSessionExpiration || 0; //Server-imposed || user-defined || 0 (default, no TTL on session)

	var newSessionId = crypto.randomBytes(16);
	testClient.createSession(serverSettings, newSessionId, wantedSessionExpiration, function(res){
		processRes(res, function(body){
			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code on sessionId agreement: ' + res.statusCode);
			//Check the session expiration, in addition to the status code and response body
			var currentSessionExpiration = res.headers['hpka-session-expiration'];
			if (expectedSessionExpiration != 0){
				var upperExpirationWindow = expectedSessionExpiration + 5,
					lowerExpirationWindow = expectedSessionExpiration - 5;
				assert(currentSessionExpiration >= lowerExpirationWindow && currentSessionExpiration <= upperExpirationWindow, 'Unexpected session expiration: ' + currentSessionExpiration + '; expected session expiration: ' + expectedSessionExpiration);
			} else {
				assert(currentSessionExpiration == 0, 'Unexpected non-null session expiration: ' + currentSessionExpiration);
			}
			assert.equal(body, expectedBody, 'Unexpected response body: ' + body);
			testSessionId = newSessionId;
			cb();
		});
	}, function(err){throw err;});

};

exports.sessionRevocationReq = function(cb, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || ('SessionId revoked');
	var expectedStatusCode = _expectedStatusCode || 200;

	testClient.revokeSession(serverSettings, testSessionId, function(res){
		processRes(res, function(body){
			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code: ' + res.statusCode);
			assert.equal(body, expectedBody, 'Unexpected response body on session revocation: ' + body);
		});
	}, function(err){throw err;});

};

// How to ensure that a SessionReq is used
exports.sessionAuthenticatedReq = function(cb, _expectedBody, _expectedStatusCode){
	if (typeof cb != 'function') throw new TypeError('cb must be a function');

	if (_expectedBody && !isString(_expectedBody)) throw new TypeError('when defined, _expectedBody must be a non-null string');
	validStatusCode(_expectedStatusCode);

	var expectedBody = _expectedBody || ('Authenticated as : ' + testUsername);
	var expectedStatusCode = _expectedStatusCode || 200;

	// TODO
	//Build a sessionPayload using hpka
	//Initiate request with performReq

	testClient.request(serverSettings, function(res){
		processRes(res, function(body){
			assert.equal(res.statusCode, expectedStatusCode, 'Unexpected status code: ' + expectedStatusCode);
			assert.equal(body, expectedBody, 'Unexpected response body on Session authenticated request: ' + body);
			cb();
		});
	}, function(err){throw err;});
};

exports.getUserSessions = function(){
	var s;
	try {
		s = testClient.getSessions();
	} catch (e){
		console.error(e.message);
		return;
	}
	return s;
};

exports.getUserSessionsReference = function(){
	var r;
	try {
		r = testClient.getSessionsReference();
	} catch (e){
		console.error(e.message);
		return;
	}
	return r;
};

exports.setUserSessions = function(_s, merge){
	testClient.setSessions(_s, merge);
}