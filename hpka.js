var cryptopp;
try {
	cryptopp = require('cryptopp');
} catch (e){

}
var sodium;
try {
	sodium = require('sodium');
} catch (e){

}
//FormData. Renaming it this way because I'm afraid it will conflict with the original FormData in case of usage in node-webkit
var fd;
try {
	fd = require('form-data');
} catch (e){

}

if (!(sodium || cryptopp)) throw new TypeError('No sodium or cryptopp modules found. At least one of them must be installed');

var fs = require('fs');
var Buffer = require('buffer').Buffer;
var http = require('http');
var https = require('https');
var url = require('fast-url-parser');

exports.supportedAlgorithms = function(){
	var algos = [];
	if (cryptopp){
		algos.push('ecdsa');
		algos.push('rsa');
		algos.push('dsa');
	}
	if (sodium){
		algos.push('ed25519');
	}
	return algos;
}

var getCurveID = function(curveName){
	//Prime curves
	if (curveName == 'secp112r1') return 0x01;
	else if (curveName == 'secp112r2') return 0x02;
	else if (curveName == 'secp128r1') return 0x03;
	else if (curveName == 'secp128r2') return 0x04;
	else if (curveName == 'secp160r1') return 0x05;
	else if (curveName == 'secp160r2') return 0x06;
	else if (curveName == 'secp160k1') return 0x07;
	else if (curveName == 'secp192r1') return 0x08;
	else if (curveName == 'secp192k1') return 0x09;
	else if (curveName == 'secp224r1') return 0x0A;
	else if (curveName == 'secp224k1') return 0x0B;
	else if (curveName == 'secp256r1') return 0x0C;
	else if (curveName == 'secp256k1') return 0x0D;
	else if (curveName == 'secp384r1') return 0x0E;
	else if (curveName == 'secp521r1') return 0x0F; //End of prime curves, first binary curve
	else if (curveName == 'sect113r1') return 0x80;
	else if (curveName == 'sect113r2') return 0x81;
	else if (curveName == 'sect131r1') return 0x82;
	else if (curveName == 'sect131r2') return 0x83;
	else if (curveName == 'sect163r1') return 0x84;
	else if (curveName == 'sect163r2') return 0x85;
	else if (curveName == 'sect163k1') return 0x86;
	else if (curveName == 'sect193r1') return 0x87;
	else if (curveName == 'sect193r2') return 0x88;
	else if (curveName == 'sect233r1') return 0x89;
	else if (curveName == 'sect233k1') return 0x8A;
	else if (curveName == 'sect239r1') return 0x8B;
	else if (curveName == 'sect283r1') return 0x8C;
	else if (curveName == 'sect283k1') return 0x8D;
	else if (curveName == 'sect409r1') return 0x8E;
	else if (curveName == 'sect409k1') return 0x8F;
	else if (curveName == 'sect571r1') return 0x90;
	else if (curveName == 'sect571k1') return 0x91;
	else return undefined;
};

var getCurveName = function(curveID){
	//Prime curves
	if (curveID == 0x01) return 'secp112r1';
	else if (curveID == 0x02) return 'secp112r2';
	else if (curveID == 0x03) return 'secp128r1';
	else if (curveID == 0x04) return 'secp128r2';
	else if (curveID == 0x05) return 'secp160r1';
	else if (curveID == 0x06) return 'secp160r2';
	else if (curveID == 0x07) return 'secp160k1';
	else if (curveID == 0x08) return 'secp192r1';
	else if (curveID == 0x09) return 'secp192k1';
	else if (curveID == 0x0A) return 'secp224r1';
	else if (curveID == 0x0B) return 'secp224k1';
	else if (curveID == 0x0C) return 'secp256r1';
	else if (curveID == 0x0D) return 'secp256k1';
	else if (curveID == 0x0E) return 'secp384r1';
	else if (curveID == 0x0F) return 'secp521r1';
	else if (curveID == 0x80) return 'sect113r1'; //End of prime curves, first binary curve
	else if (curveID == 0x81) return 'sect113r2';
	else if (curveID == 0x82) return 'sect131r1';
	else if (curveID == 0x83) return 'sect131r2';
	else if (curveID == 0x84) return 'sect163r1';
	else if (curveID == 0x85) return 'sect163r2';
	else if (curveID == 0x86) return 'sect163k1';
	else if (curveID == 0x87) return 'sect193r1';
	else if (curveID == 0x88) return 'sect193r2';
	else if (curveID == 0x89) return 'sect233r1';
	else if (curveID == 0x8A) return 'sect233k1';
	else if (curveID == 0x8B) return 'sect239r1';
	else if (curveID == 0x8C) return 'sect283r1';
	else if (curveID == 0x8D) return 'sect283k1';
	else if (curveID == 0x8E) return 'sect409r1';
	else if (curveID == 0x8F) return 'sect409k1';
	else if (curveID == 0x90) return 'sect571r1';
	else if (curveID == 0x91) return 'sect571k1';
	else return undefined;
};

var getVerbId = function(verb){
	if (typeof verb != 'string') throw new TypeError('verb must be a string');
	verb = verb.toLowerCase();
	if (verb == 'get') return 0x01;
	else if (verb == 'post') return 0x02;
	else if (verb == 'put') return 0x03;
	else if (verb == 'delete') return 0x04;
	else if (verb == 'head') return 0x05;
	else if (verb == 'trace') return 0x06;
	else if (verb == 'options') return 0x07;
	else if (verb == 'connect') return 0x08;
	else if (verb == 'patch') return 0x09;
	else return undefined;
};

var getVerbFromId = function(verbID){
	if (typeof verbID != 'number') throw new TypeError('verbID must be a number');
	if (verbID == 0x01) return 'get';
	else if (verbID == 0x02) return 'post';
	else if (verbID == 0x03) return 'put';
	else if (verbID == 0x04) return 'delete';
	else if (verbID == 0x05) return 'head';
	else if (verbID == 0x06) return 'trace';
	else if (verbID == 0x07) return 'options';
	else if (verbID == 0x08) return 'connect';
	else if (verbID == 0x09) return 'patch';
	else return undefined;
};

/*
* SERVER METHODS
*/

//Extracting all request details from the blob. Cf HPKA spec
//Note about buffers, indexes, and lack of checks :
var processReqBlob = function(pubKeyBlob){
	var buf = new Buffer(pubKeyBlob, 'base64');
	var byteIndex = 0;
	//Reading the version number
	var versionNumber = buf[byteIndex];
	byteIndex++;
	//Reading the timestamp
	var timestampLeft, timestampRight;
	timeStampLeft = buf.readUInt32BE(byteIndex);
	byteIndex += 4;
	timeStampRight = buf.readUInt32BE(byteIndex);
	byteIndex += 4;
	var timeStamp = joinUInt(timeStampLeft, timeStampRight);
	//timeStamp *= 1000;
	//Checking that the signature isn't older than 120 seconds
	var actualTimestamp = Date.now();
	//actualTimestamp -= actualTimestamp % 1000;
	actualTimestamp = Math.floor(actualTimestamp / 1000);
	//console.log('Actual timestamp : ' + actualTimestamp);
	//console.log('Req timestamp : ' + timeStamp);
	if (actualTimestamp >= timeStamp + 120) throw new RangeError("Request is too old");
	//if ((actualTimestamp > timeStamp + 120) || (actualTimestamp < timeStamp - 30)) throw new TypeError("Request is too old or ahead of time");
	//Reading the username length
	var usernameLength = buf[byteIndex];
	byteIndex++;
	//Reading the username
	var username = buf.toString('utf8', byteIndex,  byteIndex + usernameLength);
	byteIndex += usernameLength;
	//Reading the action type
	var actionType = buf[byteIndex];
	byteIndex++;
	if (!(actionType >= 0x00 && actionType <= 0x05)){
		throw new RangeError('invalid actionType');
	}
	//Reading the key type
	var keyType = buf[byteIndex];
	byteIndex++;
	//Initializing the result object
	var req = {};
	req.username = username;
	req.actionType = actionType;
	req.timeStamp = timeStamp;
	//var byteIndex = 4;
	if (keyType == 1){ //ECDSA case
		//Reading the x and y coordinates of the public point
		var publicPtXLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var xVal, yVal;
		xVal = buf.toString('hex', byteIndex, byteIndex + publicPtXLength);
		byteIndex += publicPtXLength;
		var publicPtYLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		yVal = buf.toString('hex', byteIndex, byteIndex + publicPtYLength);
		byteIndex += publicPtYLength;
		//Reading the curveID
		var curveId = buf.readUInt8(byteIndex);
		byteIndex++;

		//Building public key object
		var curveName = getCurveName(curveId);

		req.keyType = 'ecdsa';
		req.curveName = curveName;
		req.point = {};
		req.point.x = xVal;
		req.point.y = yVal;
	} else if (keyType == 2){ //RSA case
		req.keyType = 'rsa';
		var modulusLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var modulus = buf.toString('hex', byteIndex, byteIndex + modulusLength);
		byteIndex += modulusLength;
		var publicExpLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var publicExponent = buf.toString('hex', byteIndex, byteIndex + publicExpLength);
		byteIndex += publicExpLength;

		req.publicExponent = publicExponent;
		req.modulus = modulus;
	} else if (keyType == 4){ //DSA case
		req.keyType = 'dsa';
		var primeFieldLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var primeField = buf.toString('hex', byteIndex, byteIndex + primeFieldLength);
		byteIndex += primeFieldLength;
		var dividerLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var divider = buf.toString('hex', byteIndex, byteIndex + dividerLength);
		byteIndex += dividerLength;
		var baseLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var base = buf.toString('hex', byteIndex, byteIndex + baseLength);
		byteIndex += baseLength;
		var publicElementLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var publicElement = buf.toString('hex', byteIndex, byteIndex + publicElementLength);
		byteIndex += publicElementLength;

		req.primeField = primeField;
		req.divider = divider;
		req.base = base;
		req.publicElement = publicElement;
	} else if (keyType == 8){
		req.keyType = 'ed25519';
		var publicKeyLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var publicKey = buf.toString('hex', byteIndex, byteIndex + publicKeyLength);
		byteIndex += publicKeyLength;

		req.publicKey = publicKey;
	} else throw new TypeError('Unknown key type');
	if (actionType == 0x04 || actionType == 0x05){ //Session-id agreement or revocation
		var sessionIdLength, sessionId;
		//Reading the sessionId's length
		sessionIdLength = buf[byteIndex];
		byteIndex++;
		//Reading the sessionId
		sessionId = buf.toString('utf8', byteIndex, byteIndex + sessionIdLength);
		byteIndex += sessionIdLength;

		req.sessionId = sessionId;

		if (actionType == 0x04){
			//Calc remaining bytes
			var rem = remainingBytes();
			if (rem != 8) return req;
			//Extract timestamp
			var expLeft = buf.readUInt32BE(byteIndex);
			byteIndex += 4;
			var expRight = buf.readUInt32BE(byteIndex);
			byteIndex += 4;
			//Check that it's in the future
			var expirationTimestamp = joinUInt(expLeft, expRight);
			if (expirationTimestamp < Date.now()){
				throw new RangeError('expiration is already past');
			}
			req.sessionExpiration = expirationTimestamp;
		}
	}
	return req;

	function remainingBytes(){
		return buf.length - byteIndex;
	}
};

//If buffer, take it as is. If string, assume it's base64-encoded
function processSessionBlob(sessionBlob){
	var sessionBuf;
	if (Buffer.isBuffer(sessionBlob)) sessionBuf = sessionBlob;
	else if (typeof sessionBlob == 'string') sessionBuf = new Buffer(sessionBlob, 'base64');
	else throw new TypeError('invalid type for sessionBlob');

	var byteIndex = 0;

	//Reading the version number
	var versionNumber = sessionBuf[byteIndex];
	byteIndex++;
	//Reading username length
	var usernameLength = sessionBuf[byteIndex];
	byteIndex++;
	//Reading username
	var username = sessionBuf.toString('utf8', byteIndex, byteIndex + usernameLength);
	byteIndex += usernameLength;
	//Reading timestamp
	var timestampLeft, timestampRight;
	timestampLeft = sessionBuf.readUInt32BE(byteIndex);
	byteIndex += 4;
	timestampRight = sessionBuf.readUInt32BE(byteIndex);
	byteIndex += 4;
	var timestamp = joinUInt(timestampLeft, timestampRight);
	var currentTimestamp = Math.floor(Date.now() / 1000);
	if (currentTimestamp >= timestamp + 120) throw new RangeError('Request is too old');
	//Reading sessionId length
	var sessionIdLength = sessionBuf[byteIndex];
	byteIndex++;
	//Reading sessionId
	var sessionId = sessionBuf.toString('utf8', byteIndex, byteIndex + sessionIdLength);
	byteIndex += sessionIdLength;

	return {username: username, timestamp: timestamp, sessionId: sessionId};
}

/*
* req : object containing all the public key information that will be used to verify the signature
* reqBlob : the req blob of which we will verify the signature, string encoded in base64
* signature : the signature that we will verify, corresponding to reqBlob, hex-encoded string
* callback : callback function taking a boolean indicating the validity of the signature
*/
var verifySignatureWithoutProcessing = function(req, reqBlob, httpReq, signature, callback){
	if (!callback) console.log('Callback not received');
	//Checking if the key type is ECDSA
	//console.log('Parsed req : ' + JSON.stringify(req));
	//console.log('Verfying signature');
	var signedBlob = appendHostAndPathFromReq(reqBlob, httpReq);
	/*if (req.keyType == 'ed25519'){
		console.log('reqBlob\n' + (new Buffer(reqBlob, 'base64')).toString('hex'));
		console.log('signedBlob\n' + signedBlob.toString('hex'));
	}*/
	//console.log('reqBlob\n' + (new Buffer(reqBlob, 'base64')).toString('hex'));
	//console.log('signedBlob\n' + signedBlob.toString('hex'));
	//console.log('signature\n' + signature);
	if (!signedBlob){
		console.log('Error: can\'t get the blob of which we have to check the authenticity');
		console.log('reqBlob:\n' + JSON.stringify(reqBlob));
		console.log('url: ' + httpReq.url + '\nhostname: ' + httpReq.headers.hostname + '\nhost: ' + httpReq.headers.host);
		process.exit(1);
	}
	//console.log('Blob to verify: ' + signedBlob.toString('utf8'));
	if ((req.keyType == 'ecdsa' || req.keyType == 'rsa' || req.keyType == 'dsa') && !cryptopp){
		req.err = 'ECDSA, RSA and DSA are not supported since cryptopp is not installed';
		req.errcode = 12;
		callback(true); //Even though the signature can't be verified. If callback(false) was called, the middleware will throw an "invalid signature" message to the client
		return;
	}
	if (req.keyType == 'ed25519' && !sodium){
		req.err = 'Ed25519 are not supported since sodium is not installed';
		req.errcode = 12;
		callback(true); //Even though the signature can't be verified. If callback(false) was called, the middleware will throw an "invalid signature" message to the client
		return;
	}
	if (req.keyType == 'ecdsa'){
		if (req.curveName.indexOf('secp') > -1){ //Checking is the curve is a prime field one
			var isValid = cryptopp.ecdsa.prime.verify(signedBlob.toString('hex'), (new Buffer(signature, 'base64')).toString('hex'), req.point, req.curveName, 'sha1');
			callback(isValid);
		} else if (req.curveName.indexOf('sect') > -1){ //Binary curves aren't supported in ECDSA on binary fields in the node-cryptopp binding lib v0.1.2
			throw new TypeError("Unsupported curve type. See cryptopp README page");
		} else throw new TypeError("Unknown curve type");
	} else if (req.keyType == 'rsa'){
		var isValid = cryptopp.rsa.verify(signedBlob.toString('hex'), (new Buffer(signature, 'base64')).toString('hex'), req.modulus, req.publicExponent, undefined);
		callback(isValid);
	} else if (req.keyType == 'dsa'){
		var isValid = cryptopp.dsa.verify(signedBlob.toString('hex'), (new Buffer(signature, 'base64')).toString('hex'), req.primeField, req.divider, req.base, req.publicElement);
		callback(isValid)
	} else if (req.keyType == 'ed25519'){
		var isValid = sodium.api.crypto_sign_verify_detached(new Buffer(signature, 'base64'), signedBlob, new Buffer(req.publicKey, 'hex'));
		callback(isValid);
		/*if (typeof signedMessage === 'undefined') {callback(false); return;}
		//Note: the signed message is a Base64 encoded string, hence the content of signedMessage buffer is the "already encoded" base64 string.
		if (signedMessage.toString('ascii') == reqBlob) callback(true);
		else callback(false);*/
	} else throw new TypeError("Unknown key type");
};

//External / out-of-context signature validation. Note: reqUrl must be a full URL (with protocol and everything)
//This function throws an exception if the reqBlob is marlformed, or returns an error as first parameter of the callback
var verifySignature = function(reqBlob, signature, reqUrl, method, callback){
	if (typeof reqBlob != 'string') throw new TypeError('reqBlob must be a base64 string');
	if (!(Buffer.isBuffer(signature) || typeof signature == 'string')) throw new TypeError('signature must either be a buffer or a string');
	if (typeof reqUrl != 'string') throw new TypeError('reqUrl must be a string');
	if (typeof method != 'string') throw new TypeError('method must be a string');

	var req;
	try {
		req = processReqBlob(reqBlob);
	} catch (e){
		if (!callback) throw e;
		callback(e);
		return;
	}
	var reqUrlStr = reqUrl.toString('utf8'); //Start after the first byte (being the verbId);
	var parsedUrl = url.parse(reqUrlStr);
	var httpReqMimic = {
		headers: {
			host: parsedUrl.hostname || parsedUrl.host
		},
		url: parsedUrl.path || parsedUrl.pathname,
		method: method
	};
	verifySignatureWithoutProcessing(req, reqBlob, httpReqMimic, signature, function(isValid){
		callback(undefined, isValid, req.username, req);
	});
};

exports.verifySignature = verifySignature;

//Expressjs middlware builder
/* Config object signature
{
	loginCheck: function(HPKAReq, res, callback(isValid)),
	registration: function(HPKAReq, res),
	deletion: function(HPKAReq, res),
	keyRotation: function(HPKAReq, RotationReq, res)
}
*/
exports.expressMiddleware = function(loginCheck, registration, deletion, keyRotation, strict){
	if (!(typeof loginCheck == 'function' && typeof registration == 'function' && typeof deletion == 'function' && typeof keyRotation == 'function')) throw new TypeError('loginCheck and registration parameters must be event handlers (ie, functions)');
	if (!(typeof strict == 'undefined' || typeof strict == 'boolean')) throw new TypeError("When 'strict' is defined, it must be a boolean");
	var middlewareFunction = function(req, res, next){
		if (req.get('HPKA-Req') && req.get("HPKA-Signature")){
			//console.log('HPKA Headers found');
			try {
				var HPKAReqBlob = req.get("HPKA-Req"), HPKASignature = req.get("HPKA-Signature");
				var HPKAReq;
				try {
					HPKAReq = processReqBlob(HPKAReqBlob);
				} catch (e){
					console.log('HPKA-Req parsing issue; e : ' + e);
					if (strict){
						res.status(445).set('HPKA-Error', '1');
						res.send('Malformed HPKA request');
					} else {
						next();
					}
					return;
				}
				try {
					verifySignatureWithoutProcessing(HPKAReq, HPKAReqBlob, req, HPKASignature, function(isValid){
						if (isValid){
							//console.log('actionType : ' + HPKAReq.actionType);
							//console.log('Username : ' + HPKAReq.username);
							if (HPKAReq.actionType == 0){
								//Authentified HTTP request
								//Check that the user is registered and the public key valid
								//console.log('Calling login handler');
								loginCheck(HPKAReq, req, res, function(isKeyValid){
									//console.log('Is key valid : ' + isKeyValid);
									if (isKeyValid){
										req.username = HPKAReq.username;
										req.hpkareq = HPKAReq;
										next();
									} else {
										if (strict){
											res.status(445).set('HPKA-Error', '3');
											res.send('Invalid key or unregistered user');
										} else {
											next();
										}
									}
								});
								return;
							} else if (HPKAReq.actionType == 1){
								//Registration
								//console.log('Calling registration handler');
								req.hpkareq = HPKAReq;
								req.username = HPKAReq.username;
								registration(HPKAReq, req, res, next);
								return;
							} else if (HPKAReq.actionType == 2){
								//User deletion
								deletion(HPKAReq, req, res);
							} else if (HPKAReq.actionType == 3){
								//Key rotation
								var newKeyBlob = req.get('HPKA-NewKey');
								var newKeySignature = req.get('HPKA-NewKeySignature');
								var newKeySignature2 = req.get('HPKA-NewKeySignature2');
								var newKeyReq;
								try {
									newKeyReq = processReqBlob(newKeyBlob);
								} catch (e){
									res.status(445).set('HPKA-Error', '1');
									res.send('HPKA-NewKey cannot be parsed');
								}
								if (newKeyReq.actionType != 3){
									res.status(445).set('HPKA-Error', '1');
									res.send('actionType must be 0x03 in both HPKA-Reqs when rotating keys');
								}
								if (HPKAReq.username != newKeyReq.username){
									res.status(445).set('HPKA-Error', '1');
									res.send('usernames must be the same in both requests');
								}
								verifySignatureWithoutProcessing(HPKAReq, newKeyBlob, req, newKeySignature, function(newKeySignIsValid){
									if (newKeySignIsValid){
										verifySignatureWithoutProcessing(newKeyReq, newKeyBlob, req, newKeySignature2, function(newKeySign2IsValid){
											if (newKeySign2IsValid){
												req.hpkareq = HPKAReq;
												req.username = HPKAReq.username;
												keyRotation(HPKAReq, newKeyReq, req, res, next);
											} else {
												res.status(445).set('HPKA-Error', 2);
												res.send('Self-signature on new key is invalid');
											}
										});
									} else {
										res.status(445).set('HPKA-Error', 2);
										res.send('Signature of new key with actual key is invalid');
									}
								})
							} else {
								res.status(445);
								if (Number(HPKAReq.actionType) < 0 || Number(HPKAReq.actionType) > 4){
									//Invalid action types
									res.set('HPKA-Error', '8');
									res.send('Unknown action type. What the hell are you doing?');
									//console.log("Unknown action type : " + HPKAReq.actionType );
								} else {
									//Valid action type, but not implemented here yet
									res.set('HPKA-Error', '7');
									res.send('Unsupported action type. What the hell are you doing?');
								}
							}
						} else {
							//console.log('Invalid signature : ' + JSON.stringify(HPKAReq));
							if (strict){
								res.status(445).set('HPKA-Error', '2');
								res.send('Invalid signature');
							} else {
								next();
							}
						}
					});
				} catch (e){
					console.log('error : ' + e);
					if (strict){
						res.status(445).set('HPKA-Error', '2');
						res.send('Invalid signature');
					} else {
						next();
					}
					return;
				}
			} catch (e){
				console.log('error : ' + e);
				next();
			}
		} else {
			//console.log('HPKA headers not found');
			res.set('HPKA-Available', '1');
			next();
		}
	};
	return middlewareFunction;
};

//Standard HTTP middlware builder
exports.httpMiddleware = function(requestHandler, loginCheck, registration, deletion, keyRotation, strict){
	if (!(typeof requestHandler == 'function' && typeof loginCheck == 'function' && typeof registration == 'function' && typeof deletion == 'function' && typeof keyRotation == 'function')) throw new TypeError('requestHandler, loginCheck, registration, deletion and keyRotation parameters must all be functions');
	if (!(typeof strict == 'undefined' || typeof strict == 'boolean')) throw new TypeError("When 'strict' is defined, it must be a boolean");
	function writeErrorRes(res, message, errorCode){
		res.writeHead(445, {'Content-Type': 'text/plain', 'Content-Length': message.length.toString(), 'HPKA-Error': errorCode.toString()});
		res.write(message);
		res.end();
	}
	var middleware = function(req, res){
		//console.log('Headers found by the server : ' + JSON.stringify(req.headers));
		if (req.headers['hpka-req'] && req.headers['hpka-signature']){
			//console.log('HPKA headers found');
			try {
				var HPKAReqBlob = req.headers['hpka-req'], HPKASignature = req.headers['hpka-signature'];
				var HPKAReq;
				//Parsing the request
				try {
					HPKAReq = processReqBlob(HPKAReqBlob);
				} catch (e){
					console.log('parsing error, e : ' + e);
					writeErrorRes(res, 'HPKA-Req parsing error', 1);
					return;
				}
				//Checking the signature then calling the handlers according to the actionType
				try {
					verifySignatureWithoutProcessing(HPKAReq, HPKAReqBlob, req, HPKASignature, function(isValid){
						if (isValid){
							function next(){
								req.hpkareq = HPKAReq;
								req.username = HPKAReq.username;
								requestHandler(req, res);
							}

							//console.log('Signature is valid');
							//Checking the action type and calling the right handlers
							if (HPKAReq.actionType == 0x00){ //Authenticated HTTP request
								loginCheck(HPKAReq, req, res, function(isValid){
									if (isValid){
										req.username = HPKAReq.username;
										req.hpkareq = HPKAReq;
										next();
									} else {
										if (strict){
											writeErrorRes(res, 'Invalid key or unregistered user', 3);
										} else {
											next();
										}
									}
								});
							} else if (HPKAReq.actionType == 0x01){ //Registration request
								registration(HPKAReq, req, res, next);
								return;
							} else if (HPKAReq.actionType == 0x02){ //User deletion request
								deletion(HPKAReq, req, res);
								return;
							} else if (HPKAReq.actionType == 0x03){ //Key rotation request
								if (!req.headers['hpka-newkey']) writeErrorRes(res, 'Missing HPKA-NewKey header', 1);
								if (!req.headers['hpka-newkeysignature']) writeErrorRes(res, 'Missing HPKA-NewKeySignature header', 1);
								if (!req.headers['hpka-newkeysignature2']) writeErrorRes(res, 'Missing HPKA-NewKeySignature2 header', 1);
								var newKeyBlob = req.headers['hpka-newkey'];
								var newKeyReq;
								try {
									newKeyReq = processReqBlob(newKeyBlob);
								} catch (e){
									console.log('newkey parsing error, e : ' + e);
									writeErrorRes(res, 'HPKA-NewKey cannot be parsed', 1);
									return;
								}
								if (newKeyReq.actionType != 0x03) writeErrorRes(res, 'actionType must be 0x03 in both HPKA-Reqs when rotating keys', 1);
								if (HPKAReq.username != newKeyReq.username) writeErrorRes(res, 'usernames must be the same in both requests', 1);
								var newKeySignature = req.headers['hpka-newkeysignature'];
								var newKeySignature2 = req.headers['hpka-newkeysignature2'];
								//Verifying new
								verifySignatureWithoutProcessing(HPKAReq, newKeyBlob, req, newKeySignature, function(newKeySignIsValid){
									if (newKeySignIsValid){
										verifySignatureWithoutProcessing(newKeyReq, newKeyBlob, req, newKeySignature2, function(newKeySign2IsValid){
											if (newKeySign2IsValid){
												keyRotation(HPKAReq, newKeyReq, req, res, next);
												return;
											} else {
												writeErrorRes(res, 'Self-signature on new key is invalid', 2);
											}
										});
									} else {
										writeErrorRes(res, 'Signature of new key with actual key is invalid', 2);
									}
								})
							} else {
								if (Number(HPKAReq.actionType) < 0 || Number(HPKAReq.actionType) > 4){
									//Unknown actionType
									writeErrorRes(res, 'Invald actionType', 8);
								} else {
									//Unsupported actionType as of now
									writeErrorRes(res, 'Unsupported actionType', 7);
								}
							}
						} else {
							console.log('Signature is not valid');
							if (strict){
								writeErrorRes(res, 'Invalid signature.', 2);
							} else {
								requestHandler(req, res);
							}
						}
					});
				} catch (e){
					throw e;
					console.log('error : ' + e);
					writeErrorRes(res, 'Invalid signature.', 2);
					return;
				}
			} catch (e){
				throw e;
				console.log('error : ' + e);
				requestHandler(req, res);
			}
		} else {
			//console.log('HPKA headers not found');
			res.setHeader('HPKA-Available', '1');
			requestHandler(req, res);
		}
	};
	return middleware;
}

/*
* CLIENT METHODS
*/
//Create a client key pair and returns its keyring
exports.createClientKey = function(keyType, options, filename, password, doNotReturn){
	if (!(keyType == 'ecdsa' || keyType == 'dsa' || keyType == 'rsa' || keyType == 'ed25519')) throw new TypeError("Invalid key type. Must be either 'ecdsa', 'dsa' or 'rsa'");
	if (password && !(Buffer.isBuffer(password) || typeof password == 'string')) throw new TypeError('When defined, password must either be a buffer or a string');
	var keyRing;
	if (keyType == 'ecdsa' || keyType == 'dsa' || keyType == 'rsa'){ //Crypto++ cases
		keyRing = new cryptopp.KeyRing();
		if (keyType == 'ecdsa'){
			//Options should be the curve name;
			var curveId = getCurveID(options);
			if (curveId >= 0x80) {
				//Binary curves not supported yet by node-cryptopp
				throw new TypeError('Unsupported curve');
			}
		} else if (keyType == 'rsa'){
			//Options should be key size
			var keySize = Number(options);
			if (Number.isNaN(keySize)) throw new TypeError('Invalid key size');
		} else if (keyType == 'dsa'){ //DSA case
			//Options should be key size
			var keySize = Number(options);
			if (Number.isNaN(keySize)) throw new TypeError('Invalid key size');
		}
		keyRing.createKeyPair(keyType, options, filename);
	} else if (keyType == 'ed25519'){ //Ed25519
		keyRing = new sodium.KeyRing();
		keyRing.createKeyPair('ed25519');
		if (password){
			keyRing.save(filename, undefined, password);
		} else {
			keyRing.save(filename);
		}
	}
	//console.log('Generated key type : ' + keyRing.publicKeyInfo().keyType);
	if (doNotReturn){
		keyRing.clear();
		return;
	}
	return keyRing;
};

exports.changeClientKeyPassword = function(keyFilename, oldPassword, newPassword){
	if (!fs.existsSync(keyFilename)) throw new TypeError('The key file doesn\'t exist');
	if (!(Buffer.isBuffer(oldPassword)))
	var keyFileType = new Buffer(1);
	var fileHandle = fs.openSync(keyFilename, 'rs'); //'rs' flag for readSync
	var bytesRead = fs.readSync(fileHandle, keyFileType, 0, 1, 0);
	fs.closeSync(fileHandle);
	if (bytesRead != 1) throw new Error('Error while reading the key file to determine the key type. Bytes read : ' + bytesRead);

	if (keyFileType[0] != 0x06) throw new TypeError('Only Ed25519 key files can be encrypted');

	var tempKeyRing = new sodium.KeyRing();
	var pubKey;
	try {
		pubKey = tempKeyRing.load(keyFilename, undefined, oldPassword);
	} catch (e){

	}
	if (!pubKey) throw new TypeError('invalid password, or the file is not encrypted');
	tempKeyRing.save(keyFilename, undefined, newPassword);
	tempKeyRing.clear();
};

//Client object builder
exports.client = function(keyFilename, usernameVal, password, allowGetSessions){
	if (typeof usernameVal != 'string') throw new TypeError('Username must be a string');
	var keyRing, username;
	var sessions = {};
	//keyFilename is either the path to the key file, or the keyring instance
	if ((cryptopp && keyFilename instanceof cryptopp.KeyRing) || (sodium && keyFilename instanceof sodium.KeyRing)){
		username = usernameVal;
		keyRing = keyFilename;
		try {
			keyRing.publicKeyInfo()
		} catch (e){
			throw new TypeError('The passed KeyRing has no key loaded into it');
		}
	} else {
		if (!fs.existsSync(keyFilename)) throw new TypeError('Key file not found'); //Checking that the file exists
		if (password && !(Buffer.isBuffer(password) || typeof password == 'string')) throw new TypeError('When defined, password must either be a buffer or a string');
		var keyFileType = new Buffer(1);
		var fileHandle = fs.openSync(keyFilename, 'rs'); //'rs' flag for readSync
		var bytesRead = fs.readSync(fileHandle, keyFileType, 0, 1, 0);
		fs.closeSync(fileHandle);
		if (bytesRead != 1) throw new Error('Error while reading the key file to determine the key type. Bytes read : ' + bytesRead);
		//console.log('key type: ' + keyFileType.toJSON());
		if (keyFileType[0] < 0x05){ //A key file produced by cryptopp begins with "key"
			//console.log('Cryptopp keyring');
			keyRing = new cryptopp.KeyRing();
		} else if (keyFileType[0] == 0x06){ //Checking that, according the first byte, the key is a Ed25519 one
			//console.log('Sodium keyring');
			keyRing = new sodium.KeyRing();
		} else throw new TypeError('Unknown key file type: ' + keyFileType.toJSON());
		username = usernameVal;
		if (keyFileType[0] == 0x06 && password){ //Ed25519
			keyRing.load(keyFilename, undefined, password);
		} else {
			keyRing.load(keyFilename);
		}
		try{
			keyRing.publicKeyInfo();
		} catch(e){
			throw new TypeError("Invalid key file");
		}
	}

	var httpRef = http;
	var httpsRef = https;

	function stdReq(options, body, actionType, callback, errorHandler, sessionId, wantedSessionExpiration){
		if (!(options && typeof options == 'object')) throw new TypeError('"options" parameter must be defined and must be an object, according to the default http(s) node modules & node-hpka documentations');
		if (!(typeof actionType == 'number')) throw new TypeError('"actionType" parameter must be defined and must be a number');
		if (!(actionType >= 0x00 && actionType <= 0x02)) throw new TypeError('"actionType" parameter must be 0x00 <= actionType <= 0x02 when calling stdReq(). Note that keyRotations have their methods (because they require than a simple HPKA-Req blob and its signature');
		if (!(callback && typeof callback == 'function')) throw new TypeError('"callback" must be a function');
		if (errorHandler && typeof errorHandler != 'function') throw new TypeError('"errorHandler must be a function"');

		if (sessionId && !(typeof sessionId == 'string' && sessionId.length > 0 && sessionId.length < 256)) throw new TypeError('when sessionId is defined, it must be a non-null string, up to 255 bytes long');

		if (wantedSessionExpiration){
			if (typeof wantedSessionExpiration != 'number') throw new TypeError('when defined, wantedSessionExpiration must a number');
			if (Math.floor(wantedSessionExpiration) != wantedSessionExpiration) throw new TypeError('when defined, wantedSessionExpiration must be an integer number');
			if (!(wantedSessionExpiration == 0 || wantedSessionExpiration > Math.floor(Date.now() / 1000))) throw new TypeError('when defined, wantedSessionExpiration must be either equal to zero must be UTC Unix Epoch (in seconds) that is not yet past');
		}

		//Cloning the options object, before starting working on it
		options = clone(options);
		if (!options.headers) options.headers = {};
		if (!options.method) options.method = 'get';
		if (!(options.hostname && options.path)) throw new TypeError('hostname and path options must be specified');
		var hostname = options.headers['Host'] || options.headers['host'] || options.host || options.hostname;
		hostname = hostname.replace(/:\d+/, '');
		var hostnameAndPath = hostname + options.path;
		buildPayload(keyRing, username, actionType, hostnameAndPath, options.method, function(hpkaReq, signature){
			options.headers['HPKA-Req'] = hpkaReq;
			options.headers['HPKA-Signature'] = signature;
			var req;
			//Appending the headers that go with the provided body
			if (body){
				if (typeof body == 'object' && !(body instanceof fd || Buffer.isBuffer(body))){
					body = JSON.stringify(body);
					options.headers['Content-Type'] = 'application/json';
				}
				if (Buffer.isBuffer(body)){
					options.headers['Content-Length'] = body.length.toString();
				} else if (typeof body == 'string'){
					options.headers['Content-Length'] = Buffer.byteLength(body).toString();
				} else if (body instanceof fd){
					var initialHeaders = options.headers;
					options.headers = body.getHeaders();
					var initialHeadersNames = Object.keys(initialHeaders);
					for (var i = 0; i < initialHeadersNames.length; i++){
						options.headers[initialHeadersNames[i]] = initialHeaders[initialHeadersNames[i]];
					}
					options.headers['HPKA-Req'] = hpkaReq;
					options.headers['HPKA-Signature'] = signature;
				}
			}
			if (options.protocol && options.protocol == 'https'){
				options.protocol = null;
				req = httpsRef.request(options, callback);
			} else {
				options.protocol = null;
				req = httpRef.request(options, callback);
			}
			if (errorHandler) req.on('error', errorHandler);
			//Appending the body to the request
			if (body){
				if (Buffer.isBuffer(body) || typeof body == 'string'){
					req.write(body);
					req.end();
				} else if (fd && body instanceof fd){
					body.pipe(req);
				} else {
					var err = new TypeError('invalid request body type');
					if (errorHandler) errorHandler(err);
					else throw err;
					return;
				}
			} else req.end();
		});
	}

	function stdSessionReq(options, body, callback, errorHandler, sessionId){
		if (!(options && typeof options == 'object')) throw new TypeError('"options" parameter must be defined and must be an object, according to the default http(s) node modules & node-hpka documentations');
		if (!(callback && typeof callback == 'function')) throw new TypeError('callback must be a function');
		if (errorHandler && typeof errorHandler != 'function') throw new TypeError('when defined, errorHandler must be a function');

		options = clone(options);
		if (!options.headers) options.headers = {};
		if (!options.method) options.method = 'get';
		if (!(options.hostname && options.path)) throw new TypeError('hostname and path must be specified');

		var sessionPayload = buildSessionPayload(username, sessionId);

		//Appending the session header
		options.headers['HPKA-Session'] = sessionPayload;

		//Appending the headers that go with the provided body
		if (body){
			if (typeof body == 'object' && !(body instanceof fd || Buffer.isBuffer(body))){
				body = JSON.stringify(body);
				options.headers['Content-Type'] = 'application/json';
			}
			if (Buffer.isBuffer(body)){
				options.headers['Content-Length'] = body.length.toString();
			} else if (typeof body == 'string'){
				options.headers['Content-Length'] = Buffer.byteLength(body);
			} else if (body instanceof fd){
				var initialHeaders = options.headers;
				options.headers = body.getHeaders(); //Using form headers as base
				var initialHeadersNames = Object.keys(initialHeaders);
				for (var i = 0; i < initialHeadersNames.length; i++){ //Re-applying the user-provided headers
					options.headers[initialHeadersNames[i]] = initialHeaders[initialHeadersNames[i]];
				}
				options.headers['HPKA-Session'] = sessionPayload;
			}
		}

		var req;
		if (options.protocol && options.protocol == 'https'){
			options.protocol = null;
			req = httpsRef.request(options, callback);
		} else {
			options.protocol = null;
			req = httpRef.request(options, callback);
		}

		if (errorHandler) req.on('error', errorHandler);
		//Appending the body to the request
		if (body){
			if (Buffer.isBuffer(body) || typeof body == 'string'){
				req.write(body);
				req.end();
			} else if (fd && body instanceof fd){
				body.pipe(req);
			} else {
				var err = new TypeError('invalid request body type');
				if (errorHandler) errorHandler(err);
				else throw err;
				return;
			}
		} else req.end(); //No body to append. Send out the request
	}

	this.request = function(options, body, callback, errorHandler){
		if (typeof options != 'object') throw new TypeError('options must be an object');

		var hostname;
		if (typeof options.headers == 'object') hostname = options.headers['Host'] || options.headers['host']
		hostname = hostname || options.host || options.hostname;

		if (sessions[hostname]){
			stdSessionReq(options, body, callback, errorHandler, sessions[hostname]);
		} else {
			stdReq(options, body, 0x00, callback, errorHandler);
		}
	};

	this.registerUser = function(options, callback, errorHandler, body){
		stdReq(options, body, 0x01, callback, errorHandler);
	};

	this.deleteUser = function(options, callback, errorHandler){
		stdReq(options, undefined, 0x02, callback, errorHandler);
	};

	this.rotateKeys = function(options, newKeyPath, callback, password, errorHandler, body){
		if (!(options && typeof options == 'object')) throw new TypeError('"options" parameter must be defined and must be an object, according to the default http(s) node modules & node-hpka documentations');
		if (!(newKeyPath && typeof newKeyPath == 'string')) throw new TypeError('"newKeyPath" parameter must be a string, a path to the file containing the new key you want to use');
		if (!(callback && typeof callback == 'function')) throw new TypeError('"callback" must be a function');
		if (errorHandler && typeof errorHandler != 'function') throw new TypeError('when defined, errorHandler must be a function');

		//Cloning the options object, before starting working on it
		options = clone(options);
		if (!options.headers) options.headers = {};
		if (!options.method) options.method = 'get';
		if (!fs.existsSync(newKeyPath)) throw new TypeError('The key file doesn\'t exist');

		if (password && !(Buffer.isBuffer(password) || typeof password == 'string')) throw new TypeError('When defined, password must either be a buffer or a string');

		if (!((options.host || options.hostname) && options.path)) throw new TypeError('hostname and path options must be defined');
		var hostname = options.hostname || options.host.replace(/:\d+/, '');
		var hostnameAndPath = hostname + options.path;
		if (!parseHostnameAndPath(hostnameAndPath)) throw new TypeError('invalid hostname and path values');

		var signReq = function(keyRing, req, callback){
			if (!keyRing) throw new TypeError('KeyRing has not been defined');
			if (!Buffer.isBuffer(req)) throw new TypeError('req must be a buffer');
			if (!(callback && typeof callback == 'function')) throw new TypeError('Callback must be a function');

			var reqLength = req.length;
			var signedMessageLength = reqLength + Buffer.byteLength(hostnameAndPath, 'utf8') + 1; //The additional byte is for verbID
			var signedMessage = new Buffer(signedMessageLength);
			req.copy(signedMessage);
			signedMessage[reqLength] = getVerbId(options.method);
			signedMessage.write(hostnameAndPath, reqLength + 1);

			if (cryptopp && keyRing instanceof cryptopp.KeyRing){
				keyRing.sign(signedMessage.toString('utf8'), 'base64', undefined, callback);
			} else if (sodium && keyRing instanceof sodium.KeyRing) {
				keyRing.sign(signedMessage, function(signature){
					callback(signature.toString('base64'));
				}, true); //Last parameter : detached signature
			} else throw new TypeError('Unknown KeyRing type');
		};

		var newKeyRing;

		//Checking the key type before loading the NEW key in the keyring
		var keyFileType = new Buffer(1);
		var fileHandle = fs.openSync(newKeyPath, 'rs');
		var bytesRead = fs.readSync(fileHandle, keyFileType, 0, 1, 0);
		fs.closeSync(fileHandle);
		if (bytesRead != 1) throw new Error('Error while reading the key file to determine the key type. Bytes read : ' + bytesRead);

		if (keyFileType[0] < 0x05){ //Then, cryptopp keyring
			newKeyRing = new cryptopp.KeyRing();
		} else if (keyFileType[0] == 0x06) { //Then, sodium keyring
			newKeyRing = new sodium.KeyRing();
		} else throw new TypeError('Unknown key file type : ' + keyFileType.toJSON());

		if (keyFileType[0] == 0x06 && password){
			newKeyRing.load(newKeyPath, undefined, password);
		} else {
			newKeyRing.load(newKeyPath);
		}

		//First we build the payload with the known key and sign it
		buildPayload(keyRing, username, 0x03, hostnameAndPath, options.method, function(req1, signature1){
			options.headers['HPKA-Req'] = req1;
			options.headers['HPKA-Signature'] = signature1;
			//Now we build a payload with the new key
			buildPayloadWithoutSignature(newKeyRing, username, 0x03, function(req2){
				var req2Encoded = req2.toString('base64');
				options.headers['HPKA-NewKey'] = req2Encoded;
				//Now we sign the that second payload using the keypair known to the server
				signReq(keyRing, req2, function(newKeySignature1){
					options.headers['HPKA-NewKeySignature'] = newKeySignature1;
					//Now we sign it again, this time using the new key
					signReq(newKeyRing, req2, function(newKeySignature2){
						options.headers['HPKA-NewKeySignature2'] = newKeySignature2;
						//Now we clear the "old" keyRing and replace its reference to the newKeyRing
						keyRing.clear();
						keyRing = newKeyRing;
						//Now we build the HTTP/S request and send it to the server
						if (fd && body instanceof fd){
							var authHeaders = options.headers;
							options.headers = body.getHeaders();
							var authHeadersList = Object.keys(authHeaders);
							for (var i = 0; i < authHeadersList.length; i++){
								options.headers[authHeadersList[i]] = authHeaders[authHeadersList[i]];
							}
						}
						var httpReq;
						if (options.protocol && options.protocol == 'https'){
							options.protocol = null;
							httpReq = httpsRef.request(options, function(res){
								callback(res);
							});
						} else {
							options.protocol = null;
							httpReq = httpRef.request(options, function(res){
								callback(res);
							});
						}
						if (errorHandler) httpReq.on('error', errorHandler);

						if (body){
							if (typeof body == 'string' || Buffer.isBuffer(body)){
								req.write(body);
								req.end();
							} else if (fd && body instanceof fd){
								body.pipe(req);
							} else throw new TypeError('unknown body type on key rotation request');
						} else httpReq.end();
					});
				});
			});
		});
	};

	/*
	* callback receives (res, sessionIdExpiration)
	*/
	this.createSession = function(options, sessionId, wantedSessionExpiration, callback, errorHandler){
		if (typeof callback != 'function') throw new TypeError('callback must be a function');
		if (errorHandler && typeof errorHandler != 'function') throw new TypeError('when defined, errorHandler must be a function');

		stdReq(options, undefined, 0x04, function(res){
			//Checking that no hpka error occured
			if (res.statusCode == 445){
				var hpkaErrCode = res.headers['hpka-error'];
				if (errorHandler) errorHandler('HPKA-Error:' + hpkaErrCode);
				else throw new Error('HPKA-Error:' + hpkaErrCode);
				return;
			}
			//Checking that the server indeed returned a hpka-session-expiration header
			var sessionIdExpiration = res.headers['hpka-session-expiration'];
			if (typeof sessionIdExpiration == 'undefined' || sessionIdExpiration == null){
				var err = 'NOT_ACCEPTED';
				if (errorHandler) errorHandler(err);
				else throw new Error(err);
				return;
			}
			//Getting the hostname of the server we connected to
			var hostname;
			if (typeof options.headers == 'object') hostname = options.headers['Host'] || options.headers['host']
			hostname = hostname || options.host || options.hostname;

			//Saving the sessionId in the sessions hash
			sessions[hostname] = sessionId;

			callback(res, sessionIdExpiration);
		}, errorHandler, sessionId, wantedSessionExpiration);
	};

	this.revokeSession = function(options, sessionId, callback, errorHandler){
		if (typeof callback != 'function') throw new TypeError('callback must be a function');
		if (errorHandler && typeof errorHandler != 'function') throw new TypeError('when defined, errorHandler must be a function');

		stdReq(options, undefined, 0x05, function(res){
			//Checking that no hpka error occured
			if (res.statusCode == 445){
				var hpkaErrCode = res.headers['hpka-error'];
				if (errorHandler) errorHandler('HPKA-Error:' + hpkaErrCode);
				else throw new Error('HPKA-Error:' + hpkaErrCode);
				return;
			}
			//Getting the hostname of the server we connected to
			var hostname;
			if (typeof options.headers == 'object') hostname = options.headers['Host'] || options.headers['host']
			hostname = hostname || options.host || options.hostname;

			//Removing the sessionId from the sessions hash
			delete sessions[hostname];

			callback(res);
		}, errorHandler, sessionId);
	};

	this.setHttpMod = function(_httpRef){
		if (_httpRef) httpRef = _httpRef;
		else httpRef = http;
	};

	this.setHttpsMod = function(_httpsRef){
		if (_httpsRef) httpsRef = _httpsRef;
		else httpsRef = https;
	};

	this.setSessions = function(sessionsHash, merge){
		if (typeof sessionsHash != 'object') throw new TypeError('sessionsHash must be an object');
		if (merge) for (k in sessionsHash) sessions[k] = sessionsHash[k];
		else sessions = sessionsHash;
	};

	this.getSessions = function(){
		if (!allowGetSessions) throw new Error('Retrieving sessionIds is not allowed by this client instance');
		return clone(sessions);
	};

	this.getSessionsReference = function(){
		if (!allowGetSessions) throw new Error('Retrieving sessionIds is not allowed by this client instance');
		return sessions;
	};

	this.clear = function(){
		sessions = {};
		keyRing.clear();
	};
};

function buildPayloadWithoutSignature(keyRing, username, actionType, callback, encoding, sessionId, sessionExpiration){
	if (!(keyRing && ((cryptopp && keyRing instanceof cryptopp.KeyRing) || (sodium && keyRing instanceof sodium.KeyRing)))) throw new TypeError('keyRing must defined and an instance of cryptopp.KeyRing or sodium.KeyRing');
	if (!(username && typeof username == 'string')) throw new TypeError('username must be a string');
	if (username.length == 0 || username.length > 255) throw new TypeError('Username must be at least 1 byte long and at most 255 bytes long');
	if (!(actionType && typeof actionType == 'number')) actionType = 0x00;
	if (!(actionType >= 0x00 && actionType <= 0x05)) throw new TypeError('Invalid actionType. Must be 0 <= actionType <= 3');
	if (!(callback && typeof callback == 'function')) throw new TypeError('A "callback" must be given, and it must be a function');

	if (sessionId && !(typeof sessionId == 'string' && sessionId.length > 0 && sessionId.length < 256)) throw new TypeError('when defined, sessionId must be a non-null string, max 255 bytes long');
	if (sessionExpiration){
		if (typeof sessionExpiration != 'number') throw new TypeError('when defined, sessionExpiration must be a number');
		if (Math.floor(sessionExpiration) == sessionExpiration) throw new TypeError('when defined, sessionExpiration must be an integer number');
		if (sessionExpiration < 0 || (sessionExpiration > 0 && Math.floor(Date.now()/1000) > sessionExpiration)) throw new TypeError('when defined, sessionExpiration must either be equal to zero or a UTC Unix Epoch (in seconds) that is not yet passed');
	}

	if (actionType == 0x04 || actionType == 0x05){
		if (!sessionId) throw new TypeError('when actionType == 0x04 || actionType == 0x05, sessionId must be defined');
	}

	var pubKey = keyRing.publicKeyInfo();
	//console.log('Pubkey used for payload : ' + JSON.stringify(pubKey));
	//Calculating the buffer length depending on key type
	var bufferLength = 0;
	bufferLength += 1; //Version number
	bufferLength += 8; //Timestamp
	bufferLength += 1; //Username length byte
	bufferLength += username.length; //Actual username length
	bufferLength += 1; //actionType
	bufferLength += 1; //keyType
	if (pubKey.keyType == 'ecdsa'){
		bufferLength += 1; //Curve ID
		bufferLength += 2; //PublicKey.x length field
		bufferLength += pubKey.publicKey.x.length / 2; //Actual publicKey.x length. Divided by 2 because of hex encoding (that will be removed)...
		bufferLength += 2; //PublicKey.y length field
		bufferLength += pubKey.publicKey.y.length / 2; //Actual publicKey.y length. Divided by 2 because of hex encoding (that will be removed)...
	} else if (pubKey.keyType == 'rsa'){
		bufferLength += 2; //Modulus length field
		bufferLength += pubKey.modulus.length / 2; //Actual modulus length. Divided by 2 because of hex encoding
		bufferLength += 2; //PublicExp length field
		bufferLength += pubKey.publicExponent.length / 2; //Actual publicExponent length. Divided by 2 because of hex encoding
	} else if (pubKey.keyType == 'dsa'){
		bufferLength += 2; //Prime field length field
		bufferLength += pubKey.primeField.length / 2; //Actual prime field length
		bufferLength += 2; //Divider length field
		bufferLength += pubKey.divider.length / 2; //Actual divider length
		bufferLength += 2; //Base length field
		bufferLength += pubKey.base.length / 2; //Actual base length
		bufferLength += 2; //Public element length field
		bufferLength += pubKey.publicElement.length / 2; //Actual public element length
	} else if (pubKey.keyType == 'ed25519'){
		bufferLength += 2; //Public key length field
		bufferLength += pubKey.publicKey.length / 2; //Actual public key length
	}
	if (actionType == 0x04 || actionType == 0x05){
		//Add sessionId
		bufferLength += 1 + sessionId.length;
		//Add wantedSessionExpiration if provided and actionType == 0x04
		if (actionType == 0x04 && sessionExpiration) bufferLength += 8;
	}
	//bufferLength += 10; //The 10 random bytes appended to the end of the payload; augments signature's entropy
	//Building the payload
	//console.log('Req payload length : ' + bufferLength);
	var buffer = new Buffer(bufferLength);
	var offset = 0;
	//Writing protocol version
	buffer[0] = 0x01;
	offset++;
	//Writing the timestamp
	var timestamp = Math.floor(Number(Date.now()) / 1000);
	//console.log('Timestamp at buildPayload : ' + timestamp);
	var timestampParts = splitUInt(timestamp);
	buffer.writeUInt32BE(timestampParts.left, offset);
	offset += 4;
	buffer.writeUInt32BE(timestampParts.right, offset);
	offset += 4;
	//Writing the username length, then the username itself
	buffer.writeUInt8(username.length, offset);
	offset++;
	buffer.write(username, offset, offset + username.length, 'ascii');
	offset += username.length;
	//Writing the actionType
	buffer.writeUInt8(actionType, offset);
	offset++;
	if (pubKey.keyType == 'ecdsa'){
		//Writing the key type
		buffer.writeUInt8(0x01, offset);
		offset++;
		//Writing publicKey.x
		buffer.writeUInt16BE(pubKey.publicKey.x.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicKey.x, offset, 'hex');
		offset += pubKey.publicKey.x.length / 2;
		//Writing publicKey.y
		buffer.writeUInt16BE(pubKey.publicKey.y.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicKey.y, offset, 'hex');
		offset += pubKey.publicKey.y.length / 2;
		//Writing the curveID
		buffer.writeUInt8(getCurveID(pubKey.curveName), offset);
		offset++;
	} else if (pubKey.keyType == 'rsa'){
		//Writing the key type
		buffer.writeUInt8(0x02, offset);
		offset++;
		//console.log('RSA params :\nModulus : ')
		//Writing the modulus
		buffer.writeUInt16BE(pubKey.modulus.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.modulus, offset, 'hex');
		offset += pubKey.modulus.length / 2;
		//Writing the public exponent
		buffer.writeUInt16BE(pubKey.publicExponent.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicExponent, offset, 'hex');
		offset += pubKey.publicExponent.length / 2;
	} else if (pubKey.keyType == 'dsa'){
		//Writing the key type
		buffer.writeUInt8(0x04, offset);
		offset++;
		//Mwaaaaaa3, why does DSA need so much variables....
		//Writing the prime field
		buffer.writeUInt16BE(pubKey.primeField.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.primeField, offset, 'hex');
		offset += pubKey.primeField.length / 2;
		//Writing the divider
		buffer.writeUInt16BE(pubKey.divider.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.divider, offset, 'hex');
		offset += pubKey.divider.length / 2;
		//Writing the base
		buffer.writeUInt16BE(pubKey.base.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.base, offset, 'hex');
		offset += pubKey.base.length / 2;
		//Writing public element
		buffer.writeUInt16BE(pubKey.publicElement.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicElement, offset, 'hex');
		offset += pubKey.publicElement.length / 2;
	} else if (pubKey.keyType == 'ed25519'){
		//Writing key type
		buffer.writeUInt8(0x08, offset);
		offset++;
		//Writing public key
		buffer.writeUInt16BE(pubKey.publicKey.length / 2, offset);
		offset += 2;
		buffer.write(pubKey.publicKey.toUpperCase(), offset, 'hex');
		offset += pubKey.publicKey.length / 2;
	} else throw new TypeError('Unknown key type : ' + pubKey.keyType);

	if (actionType == 0x04 || actionType == 0x05){
		buffer[offset] = sessionId.length;
		offset++;
		buffer.write(sessionId, offset, offset + sessionId.length);
		offset += sessionId.length;
		if (actionType == 0x04 && sessionExpiration){
			var expirationParts = splitUInt(sessionExpiration);
			buffer.writeUInt32BE(expirationParts.left, offset);
			offset += 4;
			buffer.writeUInt32BE(expirationParts.right, offset);
			offset += 4;
		}
	}

	var req = (encoding ? buffer.toString(encoding) : buffer);
	callback(req);
}

function buildPayload(keyRing, username, actionType, hostnameAndPath, verb, callback, sessionId, sessionExpiration){
	if (!(hostnameAndPath && typeof hostnameAndPath == 'string' && parseHostnameAndPath(hostnameAndPath))) throw new TypeError('hostnameAndPath must be a valid string with hostname and path of the request concatenated');
	if (!(typeof verb == 'string' && getVerbId(verb))) throw new TypeError('invalid HTTP verb');
	if (!(callback && typeof callback == 'function')) throw new TypeError('callback must be a function');
	buildPayloadWithoutSignature(keyRing, username, actionType, function(req){
		//Note : req is already base64 encoded at this point...
		var reqEncoded = req.toString('base64');
		var reqByteLength = req.length;
		var signedMessageLength = reqByteLength + Buffer.byteLength(hostnameAndPath, 'utf8') + 1; //The one additional byte is for the verbID
		var signedMessage = new Buffer(signedMessageLength);
		req.copy(signedMessage);
		signedMessage[reqByteLength] = getVerbId(verb);
		signedMessage.write(hostnameAndPath, reqByteLength + 1);
		//console.log('Signed payload:\n' + signedMessage.toString('hex'));
		var pubKey = keyRing.publicKeyInfo();
		var keyType = pubKey.keyType;
		if (keyType == 'rsa' || keyType == 'dsa' || keyType == 'ecdsa'){
			keyRing.sign(signedMessage.toString('utf8'), 'base64', undefined, function(signature){
				callback(reqEncoded, signature); //node-cryptopp returns the signatures already base64-encoded
			});
		} else if (keyType == 'ed25519'){
			keyRing.sign(signedMessage, function(signature){
				if (!(Buffer.isBuffer(signature) && signature.length == sodium.api.crypto_sign_BYTES)) throw new TypeError('Invalid signature: ' + signature);
				callback(reqEncoded, signature.toString('base64'));
			}, true); //Last parameter : detached signature
		} else throw new TypeError('Unknown key type : ' + keyType);
	});
}

exports.buildPayload = buildPayload;

function buildSessionPayload(username, sessionId){
	if (typeof username == 'string') throw new TypeError('username must be a string');
	if (username.length == 0 || username.length > 255) throw new TypeError('username must be at least 1 byte long and at most 255 bytes long');
	if (!(Buffer.isBuffer(sessionId) || typeof sessionId == 'string')) throw new TypeError('sessionId must either be a buffer or a string');
	if (sessionId.length == 0 || sessionId.length > 255) throw new TypeError('sessionId must be at least 1 byte long and at most 255 bytes long');

	/*
	* 1 version byte
	* 1 username length byte
	* 8 timestamp bytes
	* 1 sessionId length byte
	*/
	var minSize = 11;

	var payloadBuf = new Buffer(username.length + sessionId.length + minSize);
	var byteIndex = 0;
	//Writing version number
	payloadBuf[byteIndex] = 0x01;
	byteIndex++;
	//Writing username length
	payloadBuf[byteIndex] = username.length;
	byteIndex++;
	//Writing username
	payloadBuf.write(username, byteIndex);
	byteIndex += username.length;
	//Writing timestamp
	var timestamp = Math.floor(Date.now()/1000);
	var timestampParts = splitUInt(timestamp);
	payloadBuf.writeUInt32BE(timestampParts.left, byteIndex);
	byteIndex += 4;
	payloadBuf.writeUInt32BE(timestampParts.right, byteIndex);
	byteIndex += 4;
	//Writing sessionId length
	payloadBuf[byteIndex] = sessionId.length;
	byteIndex++;
	//Writing sessionId
	if (Buffer.isBuffer(sessionId)){
		sessionId.copy(payloadBuf, byteIndex);
	} else {
		payloadBuf.write(sessionId, byteIndex);
	}
	byteIndex += sessionId.length;

	return payloadBuf.toString('base64');
}

function parseHostnameAndPath(s){
	if (!(s && typeof s == 'string')) return false;
	var seperationIndex = s.indexOf('/');
	if (seperationIndex == -1) return false;
	var hostname = s.substring(0, seperationIndex - 1);
	var path = s.substring(seperationIndex);
	return {hostname: hostname, path: path};
}

function getBase64ByteLength(base64){
	if (!isValidBase64(base64)) throw new TypeError('invalid base64 string');
	var missingBytes = 0;
	if (base64.indexOf('=') > -1) missingBytes = 1;
	if (base64.indexOf('==') > -1) missingBytes = 2;
	return 3 * (base64.length / 4) - missingBytes;
}

var TwoPower16 = 1 << 16;
var TwoPower32 = TwoPower16 * TwoPower16;

function splitUInt(n){ //Split a 53 bit integer into left and right parts
	if (!(typeof n == 'number' && Math.floor(n) == n && n >= 0)) throw new TypeError('n must positive integer number');
	var l, r;
	r = n % TwoPower32;
	l = n - r;
	return {left: l, right: r};
}

function joinUInt(left, right){
	if (!(typeof left == 'number' && Math.floor(left) == left && left >= 0 && left < TwoPower32)) throw new TypeError('left must be a positive integer with a range of 0 and 2^32-1');
	if (!(typeof right == 'number' && Math.floor(right) == right && right >= 0 && right < TwoPower32)) throw new TypeError('right must be a positive integer with a range of 0 and 2^32-1');
	var n = 0;
	n += right;
	n += left * TwoPower32;
	return n;
}

function appendHostAndPathFromReq(reqBlob, httpReq, encoding){
	if (!(typeof reqBlob == 'string' || Buffer.isBuffer(reqBlob))) throw new TypeError('reqBlob must either be a string or an object');
	if (typeof httpReq != 'object') throw new TypeError('httpReq must be an object');
	if (encoding && typeof encoding != 'string') throw new TypeError('When defined, encoding must be a string');
	var host = httpReq.headers.hostname || httpReq.headers.host.replace(/:\d+/, '');
	if (!host) return undefined;
	var path = httpReq.url;
	var hostAndPath = host + path;
	var hostAndPathLength = Buffer.byteLength(hostAndPath, 'utf8') + 1; //The additional byte is for the verbID
	var reqBuffer;
	if (!Buffer.isBuffer(reqBlob)){
		reqBuffer = new Buffer(reqBlob, encoding || 'base64');
	} else reqBuffer = reqBlob;
	var signedBlob = new Buffer(reqBuffer.length + hostAndPathLength);
	reqBuffer.copy(signedBlob);
	signedBlob[reqBuffer.length] = getVerbId(httpReq.method);
	signedBlob.write(hostAndPath, reqBuffer.length + 1);
	return signedBlob;
}

function clone(o){
	var typeO = typeof o;
	if (typeO == 'object'){
		if (Array.isArray(o)){
			var c = [];
			for (var i = 0; i < o.length; i++) c.push(clone(o[i]));
			return c;
		} else if (o instanceof Date){
			return new Date(o.getTime());
		} else if (o == null){
			return null;
		} else {
			var props = Object.keys(o);
			var c = {};
			for (var i = 0; i < props.length; i++) c[props[i]] = clone(o[props[i]])
			return c;
		}
	} else if (typeO == 'number' || typeO == 'string' || typeO == 'boolean') return o;
}
