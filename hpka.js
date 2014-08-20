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

if (!(sodium || cryptopp)) throw new TypeError('No sodium or cryptopp modules found. At least one of them must be installed');

var fs = require('fs');
var Buffer = require('buffer').Buffer;
var http = require('http');
var https = require('https');

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

/*
* SERVER METHODS
*/

//Extracting all request details from the blob. Cf HPKA spec
var processReqBlob = function(pubKeyBlob){
	var buf = new Buffer(pubKeyBlob, 'base64');
	var byteIndex = 0;
	//Reading the version number
	var versionNumber = buf[byteIndex];
	byteIndex++;
	//Reading the timestamp
	var timeStamp = buf.readInt32BE(byteIndex);
	timeStamp = timeStamp << 32;
	byteIndex += 4;
	timeStamp += buf.readInt32BE(byteIndex);
	byteIndex += 4;
	//timeStamp *= 1000;
	//Checking that the signature isn't older than 120 seconds
	var actualTimestamp = Date.now();
	//actualTimestamp -= actualTimestamp % 1000;
	actualTimestamp = Math.floor(actualTimestamp / 1000);
	//console.log('Actual timestamp : ' + actualTimestamp);
	//console.log('Req timestamp : ' + timeStamp);
	if (actualTimestamp >= timeStamp + 120) throw new TypeError("Request is too old");
	//Reading the username length
	var usernameLength = buf[byteIndex];
	byteIndex++;
	//Reading the username
	var username = buf.toString('utf8', byteIndex,  byteIndex + usernameLength);
	byteIndex += usernameLength;
	//Reading the action type
	var actionType = buf[byteIndex];
	byteIndex++;
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

		req.primeField = primeField;
		req.divider = divider;
		req.base = base;
		req.publicElement = publicElement;
	} else if (keyType == 8){
		req.keyType = 'ed25519';
		var publicKeyLength = buf.readUInt16BE(byteIndex);
		byteIndex += 2;
		var publicKey = buf.toString('hex', byteIndex, byteIndex + publicKeyLength);

		req.publicKey = publicKey;
	} else throw new TypeError('Unknown key type');
	return req;
};

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
			cryptopp.ecdsa.prime.verify(signedBlob.toString('utf8'), signature, req.point, req.curveName, 'sha1', function(isValid){
				callback(isValid);
			});
		} else if (req.curveName.indexOf('sect') > -1){ //Binary curves aren't supported in ECDSA on binary fields in the node-cryptopp binding lib v0.1.2
			throw new TypeError("Unsupported curve type. See cryptopp README page");
		} else throw new TypeError("Unknown curve type");
	} else if (req.keyType == 'rsa'){
		cryptopp.rsa.verify(signedBlob.toString('utf8'), signature, req.modulus, req.publicExponent, undefined, function(isValid){
			callback(isValid);
		});
	} else if (req.keyType == 'dsa'){
		cryptopp.dsa.verify(signedBlob.toString('utf8'), signature, req.primeField, req.divider, req.base, req.publicElement, function(isValid){
			callback(isValid);
		});
	} else if (req.keyType == 'ed25519'){
		var isValid = sodium.api.crypto_sign_verify_detached(new Buffer(signature, 'base64'), signedBlob, new Buffer(req.publicKey, 'hex'));
		callback(isValid);
		/*if (typeof signedMessage === 'undefined') {callback(false); return;}
		//Note: the signed message is a Base64 encoded string, hence the content of signedMessage buffer is the "already encoded" base64 string.
		if (signedMessage.toString('ascii') == reqBlob) callback(true);
		else callback(false);*/
	} else throw new TypeError("Unknown key type");
};

//This method is not used anywhere...
/*var verifySignature = function(reqBlob, signature, callback){
	var req = processReqBlob(reqBlob);
	verifySignatureWithoutProcessing(req, reqBlob, signature, function(isValid){
		if (isValid) callback(true, req.username, req);
		else callback(false);
	});
};

exports.verifySignature = verifySignature;*/

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
								registration(HPKAReq, req, res);
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
												keyRotation(HPKAReq, newKeyReq, req, res);
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
									//console.log("Unknown action type : " + HPKAReq.actionTyp );
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
							//console.log('Signature is valid');
							//Checking the action type and calling the right handlers
							if (HPKAReq.actionType == 0x00){ //Authenticated HTTP request
								loginCheck(HPKAReq, req, res, function(isValid){
									if (isValid){
										req.username = HPKAReq.username;
										req.hpkareq = HPKAReq;
										requestHandler(req, res);
									} else {
										if (strict){
											writeErrorRes(res, 'Invalid key or unregistered user', 3);
										} else {
											requestHandler(req, res);
										}
									}
								});
							} else if (HPKAReq.actionType == 0x01){ //Registration request
								registration(HPKAReq, req, res);
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
												keyRotation(HPKAReq, newKeyReq, req, res);
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
exports.createClientKey = function(keyType, options, filename){
	if (!(keyType == 'ecdsa' || keyType == 'dsa' || keyType == 'rsa' || keyType == 'ed25519')) throw new TypeError("Invalid key type. Must be either 'ecdsa', 'dsa' or 'rsa'");
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
		keyRing.save(filename);
	}
	//console.log('Generated key type : ' + keyRing.publicKeyInfo().keyType);
	return keyRing;
}

//Client object builder
exports.client = function(keyFilename, usernameVal){
	if (typeof usernameVal != 'string') throw new TypeError('Username must be a string');
	if (!fs.existsSync(keyFilename)) throw new TypeError('Key file not found'); //Checking that the file exists
	var keyFileType = new Buffer(1);
	var fileHandle = fs.openSync(keyFilename, 'rs'); //'rs' flag for readSync
	var bytesRead = fs.readSync(fileHandle, keyFileType, 0, 1, 0);
	fs.closeSync(fileHandle);
	if (bytesRead != 1) throw new Error('Error while reading the key file to determine the key type. Bytes read : ' + bytesRead);
	//console.log('key type: ' + keyFileType.toJSON());
	var keyRing;
	if (keyFileType[0] < 0x05){ //A key file produced by cryptopp begins with "key"
		//console.log('Cryptopp keyring');
		keyRing = new cryptopp.KeyRing();
	} else if (keyFileType[0] == 0x06){ //Checking that, according the first byte, the key is a Ed25519 one
		//console.log('Sodium keyring');
		keyRing = new sodium.KeyRing();
	} else throw new TypeError('Unknown key file type: ' + keyFileType.toJSON());
	var username = usernameVal;
	keyRing.load(keyFilename);
	try{
		keyRing.publicKeyInfo();
	} catch(e){
		throw new TypeError("Invalid key file");
	}

	var httpRef = http;
	var httpsRef = https;

	function stdReq(options, body, actionType, callback){
		if (!(options && typeof options == 'object')) throw new TypeError('"options" parameter must be defined and must be an object, according to the default http(s) node modules & node-hpka documentations');
		if (!(typeof actionType == 'number')) throw new TypeError('"actionType" parameter must be defined and must be a number');
		if (!(actionType >= 0x00 && actionType <= 0x02)) throw new TypeError('"actionType" parameter must be 0x00 <= actionType <= 0x02 when calling stdReq(). Note that keyRotations have their methods (because they require than a simple HPKA-Req blob and its signature');
		if (!(callback && typeof callback == 'function')) throw new TypeError('"callback" must be a function');
		if (!options.headers) options.headers = {};
		if (!(options.hostname && options.path)) throw new TypeError('hostname and path options must be specified')
		var hostnameAndPath = options.hostname + options.path;
		buildPayload(keyRing, username, actionType, hostnameAndPath, function(req, signature){
			options.headers['HPKA-Req'] = req;
			options.headers['HPKA-Signature'] = signature;
			var req;
			if (options.protocol && options.protocol == 'https'){
				options.protocol = null;
				req = httpsRef.request(options, function(res){
					if (callback) callback(res);
				})
			} else {
				options.protocol = null;
				req = httpRef.request(options, function(res){
					if (callback) callback(res);
				});
			}
			if (body) req.write(body);
			req.end();
		});
	}

	this.request = function(options, body, callback){
		stdReq(options, body, 0x00, callback);
	};

	this.registerUser = function(options, callback){
		stdReq(options, undefined, 0x01, callback);
	};

	this.deleteUser = function(options, callback){
		stdReq(options, undefined, 0x02, callback);
	};

	this.rotateKeys = function(options, newKeyPath, callback){
		if (!(options && typeof options == 'object')) throw new TypeError('"options" parameter must be defined and must be an object, according to the default http(s) node modules & node-hpka documentations');
		if (!(newKeyPath && typeof newKeyPath == 'string')) throw new TypeError('"newKeyPath" parameter must be a string, a path to the file containing the new key you want to use');
		if (!(callback && typeof callback == 'function')) throw new TypeError('"callback" must be a function');
		if (!options.headers) options.headers = {};
		if (!fs.existsSync(newKeyPath)) throw new TypeError('The key file doesn\'t exist');

		if (!((options.host || options.hostname) && options.path)) throw new TypeError('hostname and path options must be defined');
		var hostname = options.hostname || options.host.replace(/:\d+/, '');
		var hostnameAndPath = hostname + options.path;
		if (!parseHostnameAndPath(hostnameAndPath)) throw new TypeError('invalid hostname and path values');

		var signReq = function(keyRing, req, callback){
			if (!keyRing) throw new TypeError('KeyRing has not been defined');
			if (!Buffer.isBuffer(req)) throw new TypeError('req must be a buffer');
			if (!(callback && typeof callback == 'function')) throw new TypeError('Callback must be a function');

			var reqLength = req.length;
			var signedMessageLength = reqLength + hostnameAndPath.length;
			var signedMessage = new Buffer(signedMessageLength);
			req.copy(signedMessage);
			signedMessage.write(hostnameAndPath, reqLength);

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
		newKeyRing.load(newKeyPath);

		//First we build the payload with the known key and sign it
		buildPayload(keyRing, username, 0x03, hostnameAndPath, function(req1, signature1){
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
						var httpReq;
						if (options.protocol && options.protocol == 'https'){
							options.protocol = null;
							httpReq = https.request(options, function(res){
								callback(res);
							});
						} else {
							options.protocol = null;
							httpReq = http.request(options, function(res){
								callback(res);
							});
						}
						httpReq.end();
					});
				})
			});
		});
	};

	this.setHttpMod = function(_httpRef){
		if (_httpRef){
			httpRef = _httpRef;
		} else httpRef = http;
	};

	this.setHttpsMod = function(_httpsRef){
		if (_httpsRef){
			httpsRef = _httpsRef;
		} else httpsRef = https;
	};
};

function buildPayloadWithoutSignature(keyRing, username, actionType, callback, encoding){
	if (!(keyRing && ((cryptopp && keyRing instanceof cryptopp.KeyRing) || (sodium && keyRing instanceof sodium.KeyRing)))) throw new TypeError('keyRing must defined and an instance of cryptopp.KeyRing or sodium.KeyRing');
	if (!(username && typeof username == 'string')) throw new TypeError('username must be a string');
	if (username.length > 255) throw new TypeError('Username must be at most 255 bytes long');
	if (!(actionType && typeof actionType == 'number')) actionType = 0x00;
	if (!(actionType >= 0x00 && actionType <= 0x03)) throw new TypeError('Invalid actionType. Must be 0 <= actionType <= 3');
	if (!(callback && typeof callback == 'function')) throw new TypeError('A "callback" must be given, and it must be a function');
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
	buffer.writeInt32BE(timestamp >> 31, offset);
	offset += 4;
	buffer.writeInt32BE(timestamp, offset, true);
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

	var req = (encoding ? buffer.toString(encoding) : buffer);
	callback(req);
}

function buildPayload(keyRing, username, actionType, hostnameAndPath, callback){
	if (!(hostnameAndPath && typeof hostnameAndPath == 'string' && parseHostnameAndPath(hostnameAndPath))) throw new TypeError('hostnameAndPath must be a valid string with hostname and path of the request concatenated');
	if (!(callback && typeof callback == 'function')) throw new TypeError('callback must be a function');
	buildPayloadWithoutSignature(keyRing, username, actionType, function(req){
		//Note : req is already base64 encoded at this point...
		var reqEncoded = req.toString('base64');
		var reqByteLength = req.length;
		var signedMessageLength = reqByteLength + hostnameAndPath.length;
		var signedMessage = new Buffer(signedMessageLength);
		req.copy(signedMessage);
		signedMessage.write(hostnameAndPath, reqByteLength);
		//console.log('Signed payload: ' + signedMessage.toString('utf8'));
		var pubKey = keyRing.publicKeyInfo();
		var keyType = pubKey.keyType;
		if (keyType == 'rsa' || keyType == 'dsa' || keyType == 'ecdsa'){
			keyRing.sign(signedMessage.toString('utf8'), 'base64', undefined, function(signature){
				callback(reqEncoded, signature); //node-cryptopp returns the signatures already hex-encoded
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

function appendHostAndPathFromReq(reqBlob, httpReq, encoding){
	if (!(typeof reqBlob == 'string' || Buffer.isBuffer(reqBlob))) throw new TypeError('reqBlob must either be a string or an object');
	if (typeof httpReq != 'object') throw new TypeError('httpReq must be an object');
	if (encoding && typeof encoding != 'string') throw new TypeError('When defined, encoding must be a string');
	var host = httpReq.headers.hostname || httpReq.headers.host.replace(/:\d+/, '');
	if (!host) return undefined;
	var path = httpReq.url;
	var hostAndPathLength = host.length + path.length;
	var hostAndPath = host + path;
	var reqBuffer;
	if (!Buffer.isBuffer(reqBlob)){
		reqBuffer = new Buffer(reqBlob, encoding || 'base64');
	} else reqBuffer = reqBlob;
	var signedBlob = new Buffer(reqBuffer.length + hostAndPathLength);
	reqBuffer.copy(signedBlob);
	signedBlob.write(hostAndPath, reqBuffer.length);
	return signedBlob;
}
