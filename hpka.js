var cryptopp = require('cryptopp');
var Buffer = require('buffer').Buffer;
var http = require('http');

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
	else return 0x00;
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
	} else throw new TypeError('Unknown key type');
	return req;
};

var verifySignatureWithoutProcessing = function(req, reqBlob, signature, callback){
	//Checking if the key type is ECDSA
	if (req.keyType == 'ecdsa'){
		if (req.curveName.indexOf('secp') > -1){ //Checking is the curve is a prime field one
			cryptopp.ecdsa.prime.verify(reqBlob, signature, req.point, req.curveName, function(isValid){
				callback(isValid);
			});
		} else if (req.curveName.indexOf('sect') > -1){ //Binary curves aren't supported in ECDSA on binary fields in the node-cryptopp binding lib v0.1.2
			throw new TypeError("Unsupported curve type. See cryptopp README page");
		} else throw new TypeError("Unknown curve type");
	} else if (req.keyType == 'rsa'){
		cryptopp.rsa.verify(reqBlob, signature, req.modulus, req.publicExponent, function(isValid){
			callback(isValid);
		});
	} else if (req.keyType == 'dsa'){
		cryptopp.dsa.verify(reqBlob, signature, req.primeField, req.divider, req.base, req.publicElement, function(isValid){
			callback(isValid);
		});
	} else throw new TypeError("Unknown key type");
};

var verifySignature = function(reqBlob, signature, callback){
	var req = processReqBlob(reqBlob);
	verifySignatureWithoutProcessing(req, reqBlob, signature, function(isValid){
		if (isValid) callback(true, req.username, req);
		else callback(false);
	});
};

exports.verifySignature = verifySignature;

//Expressjs middlware builder
/* Config object signature
{
	loginCheck: function(HPKAReq, res, callback(isValid)),
	registration: function(HPKAReq, res),
	backup: function(HPKAReq, res),  // for upcoming versions
	delete: function(HPKAReq, res), // for upcoming versions
	restore: function(HPKAReq, res), // for upcoming versions
	keyRotation: function(HPKAReq, RotationReq) // for upcoming versions
}
*/
exports.middleware = function(loginCheck, registration, strict){
	if (!(typeof loginCheck == 'function' && typeof registration == 'function')) throw new TypeError('loginCheck and registration parameters must be event handlers (ie, functions)');
	if (!(typeof strict == 'undefined' || typeof strict == 'boolean')) throw new TypeError("When 'strict' is defined, it must be a boolean");
	var middlewareFunction = function(req, res, next){
		if (req.get('HPKA-Req') && req.get("HPKA-Signature")){
			console.log('HPKA Headers found');
			try {
				var HPKAReqBlob = req.get("HPKA-Req"), HPKASignature = req.get("HPKA-Signature");
				var HPKAReq;
				try {
					HPKAReq = processReqBlob(HPKAReqBlob);
				} catch (e){
					console.log('HPKA-Req parsing issue; e : ' + JSON.stringify(e));
					if (strict){
						res.status(445).set('HPKA-Error', '1');
						res.send('Malformed HPKA request');
					} else {
						next();
					}
					return;
				}
				try {
					verifySignatureWithoutProcessing(HPKAReq, HPKAReqBlob, HPKASignature, function(isValid){
						if (isValid){
							//console.log('actionType : ' + HPKAReq.actionType);
							//console.log('Username : ' + HPKAReq.username);
							if (HPKAReq.actionType == 0){
								//Authentified HTTP request
								//Check that the user is registered and the public key valid
								//console.log('Calling login handler');
								loginCheck(HPKAReq, res, function(isKeyValid){
									//console.log('Is key valid : ' + isKeyValid);
									if (isKeyValid){
										req.username = HPKAReq.username;
										req.hpkareq = HPKAReq;
										next();
									} else {
										if (strict){
											res.status(445).set('HPKA-Error', '3');
											res.send('Invalid public key');
										} else {
											next();
										}
									}
								});
								return;
							} else if (HPKAReq.actionType == 1){
								//Registration
								//console.log('Calling registration handler');
								registration(HPKAReq, res);
								return;
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
					console.log('error : ' + JSON.stringify(e));
					if (strict){
						res.status(445).set('HPKA-Error', '2');
						res.send('Invalid signature');
					} else {
						next();
					}
					return;
				}
			} catch (e){
				console.log(e);
				next();
			}
		} else {
			console.log('HPKA headers not found');
			res.set('HPKA-Available', '1');
			next();
		}
	};
	return middlewareFunction;
};

//Standard HTTP middlware builder
exports.httpMiddleware = function(requestHandler, loginCheck, registration, strict){
	if (!(typeof requestHandler == 'function' && typeof loginCheck == 'function' && typeof registration == 'function')) throw new TypeError('requestHandler, loginCheck and registration must all be functions');
	if (!(typeof strict == 'undefined' || typeof strict == 'boolean')) throw new TypeError("When 'strict' is defined, it must be a boolean");
	function writeErrorRes(res, message, errorCode){
		res.writeHead(445, {'Content-Type': 'text/plain', 'Content-Length': message.length.toString(), 'HPKA-Error': errorCode.toString()});
		res.write(message);
		res.end();
	}
	var middleware = function(req, res){
		if (req.headers['HPKA-Req'] && req.headers['HPKA-Signature']){
			console.log('HPKA headers found');
			try {
				var HPKAReqBlob = req.headers['HPKA-Req'], HPKASignature = req.headers['HPKA-Signature'];
				var HPKAReq;
				//Parsing the request
				try {
					HPKAReq = processReqBlob(HPKAReqBlob);
				} catch (e){
					writeErrorRes(res, 'HPKA-Req parsing error', 1);
					return;
				}
				//Checking the signature then calling the handlers according to the actionType
				try {
					verifySignatureWithoutProcessing(HPKAReq, HPKAReqBlob, HPKASignature, function(isValid)){
						if (isValid){
							//Checking the action type and calling the right handlers
							if (HPKAReq.actionType == 0x00){ //Authenticated HTTP request
								loginCheck(HPKAReq, res, function(isValid)){
									if (isValid){
										req.username = HPKAReq.username;
										req.hpkareq = HPKAReq;
									} else {
										if (strict){
											writeErrorRes(res, 'Invalid key', 3);
										} else {
											requestHandler(req, res);
										}
									}
								});
							} else if (HPKAReq.actionType == 0x01){ //Registration request
								registration(HPKAReq, res);
								return;
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
							if (strict){
								writeErrorRes(res, 'Invalid signature', 2);
							} else {
								requestHandler(req, res);
							}
						}
					}
				} catch (e){
					console.log('error : ' + JSON.stringify(e));
					writeErrorRes(res, 'Invalid signature', 2);
					return;
				}
			} catch (e){
				console.log('error : ' + JSON.stringify(e));
				requestHandler(req, res);
			}
		} else {
			console.log('HPKA headers not found');
			res.setHeader('HPKA-Available', '1');
			requestHandler(req, res);
		}
	};
	return middleware;
}

/*
* CLIENT METHODS
*/
//Create a client key pair
exports.createClientKey = function(filename, keyType, options){
	if (!(keyType == 'ecdsa' || keyType == 'dsa' || keyType == 'rsa')) throw new TypeError("Invalid key type. Must be either 'ecdsa', 'dsa' or 'rsa'");
	var keyPair;
	if (keyType == 'ecdsa'){
		//Options should be the curve name;
		var curveId = getCurveID(options);
		if (curveId >= 0x80) {
			//Binary curves not supported yet by node-cryptopp
			throw new TypeError('Unsupported curve');
		} else {
			keyPair = cryptopp.ecdsa.prime.generateKeyPair(curveId);
		}
	} else if (keyType == 'rsa'){
		//Options should be key size
		var keySize = Number(options);
		if (Number.isNaN(keySize)) throw new TypeError('Invalid key size');
		keyPair = cryptopp.rsa.generateKeyPair(keySize);
	} else { //DSA case
		//Options should be key size
		var keySize = Number(options);
		if (Number.isNaN(keySize)) throw new TypeError('Invalid key size');
		keyPair = cryptopp.dsa.generateKeyPair(keySize);
	}
	saveKeyPair(filename, keyPair);
}

//Client object builder
exports.client = function(keyFilename){
	var keyPair = loadKeyPair(keyFilename);
	if (!keyPair) throw new TypeError("Invalid key file");
	this.request = function(options, body, callback){
		if (!options.headers) options.headers = {};
		//options.headers["HPKA-Req"]
		//options.headers["HPKA-Signature"]
		/*
			BUILDING THE PAYLOAD
		*/
		var req = http.request(options, function(res){
			callback(res);
		});
		if (body) req.write(body);
		req.end();
	};
};

function buildPayload(keyPair, username, actionType, callback){
	if (!(typeof keyPair == 'object' && typeof username == 'string' && typeof actionType == 'number' && typeof callback == 'function')) throw new TypeError('Invalid parmeters');
	//Calculating the buffer length depending on key type
	var bufferLength = 0;
	bufferLength += 1; //Version number
	bufferLength += 8; //Timestamp
	bufferLength += 1; //Username length byte
	bufferLength += username.length; //Actual username length
	bufferLength += 1; //actionType
	bufferLength += 1; //keyType
	if (keyPair.keyType == 'ecdsa'){
		if (!(keyPair.publicKey && keyPair.publicKey.x && keyPair.publicKey.y && keyPair.privateKey && keyPair.curveName)) throw new TypeError('Invalid ECDSA key pair');
		bufferLength += 1; //Curve ID
		bufferLength += 2; //PublicKey.x length field
		bufferLength += keyPair.publicKey.x.length; //Actual publicKey.x length
		bufferLength += 2; //PublicKey.y length field
		bufferLength += keyPair.publicKey.y.length;
	} else if (keyPair.keyType == 'rsa'){
		if (!(keyPair.modulus && keyPair.publicExponent && keyPair.privateExponent)) throw new TypeError('Invalid RSA key pair');
		bufferLength += 2; //Modulus length field
		bufferLength += keyPair.modulus.length; //Actual modulus length
		bufferLength += 2; //PublicExp length field
		bufferLength += keyPair.publicExponent.length; //Actual publicExponent length
	} else if (keyPair.keyType == 'dsa'){
		if (!(keyPair.primeField && keyPair.divider && keyPair.base && keyPair.publicElement && keyPair.privateExponent)) throw new TypeError('Invalid DSA key pair');
		bufferLength += 2; //Prime field length field
		bufferLength += keyPair.primeField.length; //Actual prime field length
		bufferLength += 2; //Divider length field
		bufferLength += keyPair.divider.length; //Actual divider length
		bufferLength += 2; //Base length field
		bufferLength += keyPair.base.length; //Actual base length
		bufferLength += 2; //Public element length field
		bufferLength += keyPair.publicElement.length; //Actual public element length
	} else throw new TypeError('Invalid key type');
	bufferLength += 10; //The 10 random bytes appended to the end of the payload; augments signature's entropy
	//Building the payload
	var buffer = new Buffer(bufferLength);
	var offset = 0;
	//Writing protocol version
	buffer[0] = 0x01;
	offset++;
	//Writing the timestamp
	var timestamp = Math.floor(Date.now / 1000);
	buffer.writeInt32BE(timestamp >> 32, offset);
	offset += 4;
	buffer.writeInt32BE(timestamp, offset, true);
	offset += 4;
	//Writing the username length, then the username itself
	buffer.writeUInt8(username.length, offset);
	offset++;
	buffer.write(username, offset, offset + username.length);
	offset += username.length;
	//Writing the actionType
	buffer.writeUInt8(actionType, offset);
	offset++;
	if (keyPair.keyType == 'ecdsa'){
		//Writing the key type
		buffer.writeUInt8(0x01, offset);
		offset++;
		//Writing publicKey.x
		buffer.writeUInt16BE(keyPair.publicKey.x.length, offset);
		offset += 2;
		buffer.write(keyPair.publicKey.x, offset, offset + keyPair.publicKey.x.length, 'hex');
		offset += keyPair.publicKey.x.length;
		//Writing publicKey.y
		buffer.writeUInt16BE(keyPair.publicKey.y.length, offset);
		offset += 2;
		buffer.write(keyPair.publicKey.y, offset, offset + keyPair.publicKey.y.length, 'hex');
		offset += keyPair.publicKey.y.length;
		//Writing the curveID
		buffer.writeUInt8(getCurveID(keyPair.curveName), offset);
		offset++;
	} else if (keyPair.keyType == 'rsa'){
		//Writing the key type
		buffer.writeUInt8(0x02, offset);
		offset++;
		//Writing the modulus
		buffer.writeUInt16BE(keyPair.modulus.length, offset);
		offset += 2;
		buffer.write(keyPair.modulus, offset, offset + keyPair.publicKey.y.length, 'hex');
		offset += keyPair.modulus.length;
		//Writing the public exponent
		buffer.writeUInt16BE(keyPair.publicExponent.length, offset);
		offset += 2;
		buffer.write(keyPair.publicExponent, offset, offset + keyPair.publicExponent.length, 'hex');
		offset += keyPair.publicExponent.length;
	} else {
		//Writing the key type
		buffer.writeUInt8(0x04, offset);
		offset++;
		//Mwaaaaaa3, why does DSA need so much variables....
		//Writing the prime field
		buffer.writeUInt16BE(keyPair.primeField.length, offset);
		offset += 2;
		buffer.write(keyPair.primeField, offset, offset + keyPair.primeField.length, 'hex');
		offset += keyPair.primeField.length;
		//Writing the divider
		buffer.writeUInt16BE(keyPair.divider.length, offset);
		offset += 2;
		buffer.write(keyPair.divider, offset, offset + keyPair.divider.length, 'hex');
		offset += keyPair.divider.length;
		//Writing the base
		buffer.writeUInt16BE(keyPair.base.length, offset);
		offset += 2;
		buffer.write(keyPair.base, offset, offset + keyPair.base.length, 'hex');
		offset += keyPair.base.length;
		//Writing public element
		buffer.writeUInt16BE(keyPair.publicElement.length, offset);
		offset += 2;
		buffer.write(keyPair.publicElement, offset, offset + keyPair.publicElement.length, 'hex');
		offset += keyPair.publicElement.length;
	}
	var randomBytes = cryptopp.randomBytes(10);
	buffer.write(randomBytes, offset, offset + 10, 'ascii');
	offset += 10;
	if (keyPair.keyType == 'ecdsa'){

	} else if (keyPair.keyType == 'rsa'){

	} else {
		
	}
}

//Loading the key pair from a file
function loadKeyPair(filename){
	var fileBuffer = fs.readFileSync(filename);
	if (!fileBuffer) throw new TypeError("File not found");
	var offset = 3;
	var keyHeader = "";
	for (var i = 0; i < 3; i++){
		keyHeader += fileBuffer[i];
	}
	if (keyHeader != "key") throw new TypeError("Invalid key file");
	var keyPair = {};
	var keyType = fileBuffer[offset];
	offset++;
	if (keyType == 0x00){ //ECDSA
		keyPair.keyType = "ecdsa";
		//Reading the curveId, then getting the curve name
		var curveID = fileBuffer[offset];
		offset++;
		var curveName = getCurveName(curveID);
		//Reading publicPoint.x
		var publicPtXLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var xVal = fileBuffer.toString('ascii', offset, offset + publicPtXLength);
		offset += publicPtXLength;
		//Reading publicPoint.y
		var publicPtYLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var yVal = fileBuffer.toString('ascii', offset, offset + publicPtYLength);
		offset += publicPtYLength;
		//Reading the privateKey
		var privateKeyLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var privateKey = fileBuffer.toString('ascii', offset, offset + privateKeyLength);
		offset += privateKeyLength;
		//Setting keyPair attributes
		keyPair.curveName = curveName;
		keyPair.publicKey = {};
		keyPair.publicKey.x = xVal;
		keyPair.publicKey.y = yVal;
		keyPair.privateKey = privateKey;
	} else if (keyType == 0x01){ //RSA
		keyPair.keyType = "rsa";
		//Reading the modulus
		var modulusLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var modulus = fileBuffer.toString('ascii', offset, offset + modulusLength);
		offset += modulusLength;
		//Reading the public exponent
		var publicExpLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var publicExponent = fileBuffer.toString('ascii', offset, offset + publicExpLength);
		offset += publicExpLength;
		//Reading the private exponent
		var privateKeyLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var privateExponent = fileBuffer.toString('ascii', offset, offset + privateKeyLength);
		offset += privateKeyLength;
		//Setting keyPair attributes
		keyPair.modulus = modulus;
		keyPair.publicExponent = publicExponent;
		keyPair.privateExponent = privateExponent;
	} else if (keyType == 0x02){ //DSA
		keyPair.keyType = "dsa";
		//Reading the prime field
		var primeFieldLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var primeField = fileBuffer.toString('ascii', offset, offset + primeFieldLength);
		offset += primeFieldLength;
		//Reading the divider
		var dividerLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var divider = fileBuffer.toString('ascii', offset, offset + dividerLength);
		offset += dividerLength;
		//Reading the base
		var baseLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var base = fileBuffer.toString('ascii', offset, offset + baseLength);
		offset += baseLength;
		//Reading the public element
		var publicElementLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var publicElement = fileBuffer.toString('ascii', offset, offset + publicElementLength);
		offset += publicElementLength;
		//Reading the private exponent
		var privateKeyLength = fileBuffer.readUInt16BE(offset);
		offset += 2;
		var privateKey = fileBuffer.toString('ascii', offset, offset + privateKeyLength);
		offset += privateKeyLength;
		//Writing the keyPair attributes
		keyPair.primeField = primeField;
		keyPair.divider = divider;
		keyPair.base = base;
		keyPair.publicElement = publicElement;
		keyPair.privateExponent = privateKey;
	} else throw new TypeError("Invalid key type");
	return keyPair;
}

//Writing a key pair to a file
function saveKeyPair(filename, keyPair){
	var offset = 0;
	var buffer;
	var bufferLength = 3; //3 for the first letters "key" in the file
	var keyType = keyPair.keyType;
	if (!(keyType == 'ecdsa' || keyType == 'dsa' || keyType == 'rsa')) throw new TypeError("Invalid key type. Must be either 'ecdsa', 'dsa' or 'rsa'");
	if (keyType == 'ecdsa'){
		if (!(keyPair.curveName && keyPair.publicKey && keyPair.publicKey.x && keyPair.publicKey.y && keyPair.privateKey)) throw new TypeError("Missing parameters");
		var curveID = getCurveID(keyPair.curveName);
		bufferLength += 1; //One byte for key type
		bufferLength += 1; //One byte for curveID
		bufferLength += 2 + keyPair.publicKey.x.length; //The number of bytes for the x coordinate of the public key
		bufferLength += 2 + keyPair.publicKey.y.length; //Same here for y coordinate
		bufferLength += 2 + keyPair.privateKey.length; //Same for the the private key
		buffer = new Buffer(bufferLength);
		//Writing the dummy header of I don't know what
		buffer.write("key", offset, 3);
		offset += 3;
		//Writing the key type
		buffer.writeUInt8(0x00, offset);
		offset++;
		//Writing the curveID
		buffer.writeUInt8(curveID, offset);
		offset++;
		//Writing publicKey.x's length followed by publicKey.x 
		buffer.writeUInt16BE(keyPair.publicKey.x.length, offset);
		offset += 2;
		buffer.write(keyPair.publicKey.x, offset, keyPair.publicKey.x.length);
		offset += keyPair.publicKey.x.length;
		//Same here for publicKey.y
		buffer.writeUInt16BE(keyPair.publicKey.y.length, offset);
		offset += 2;
		buffer.write(keyPair.publicKey.y, offset, keyPair.publicKey.y.length);
		offset += keyPair.publicKey.y.length;
		//Same here for privateKey
		buffer.writeUInt16BE(keyPair.privateKey.length, offset);
		offset += 2;
		buffer.write(keyPair.privateKey, offset, keyPair.privateKey.length);
		buffer += keyPair.privateKey.length;
	} else if (keyType == 'rsa'){
		if (!(keyPair.modulus && keyPair.publicExponent && keyPair.privateExponent)) throw new TypeError("Missing parameters");
		bufferLength += 1; //One byte for the key type
		bufferLength += 2 + keyPair.modulus.length;
		bufferLength += 2 + keyPair.publicExponent.length;
		bufferLength += 2 + keyPair.privateExponent.length;
		buffer = new Buffer(bufferLength);
		//Writing a dummy header
		buffer.write("key", offset, 3);
		offset += 3;
		//Writing the modulus
		buffer.writeUInt16BE(keyPair.modulus.length, offset);
		offset += 2;
		buffer.write(keyPair.modulus, offset, keyPair.modulus.length);
		offset += keyPair.modulus.length;
		//Writing the public exponent
		buffer.writeUInt16BE(keyPair.publicExponent.length, offset);
		offset += 2;
		buffer.write(keyPair.publicExponent, offset, keyPair.publicExponent.length);
		offset += keyPair.publicExponent.length;
		//Writing the private exponent
		buffer.writeUInt16BE(keyPair.privateExponent.length, offset);
		offset += 2;
		buffer.write(keyPair.privateExponent, offset, keyPair.privateExponent.length);
		offset += keyPair.privateExponent.length;
	} else { //DSA case
		if (!(keyPair.primeField && keyPair.divider && keyPair.base && keyPair.publicElement && keyPair.privateKey)) throw new TypeError("Missing parameters");
		bufferLength += 1; //One byte for the key type;
		bufferLength += 2 + keyPair.primeField.length;
		bufferLength += 2 + keyPair.divider.length;
		bufferLength += 2 + keyPair.base.length;
		bufferLength += 2 + keyPair.publicElement.length;
		bufferLength += 2 + keyPair.privateKey.length;
		buffer = new Buffer(bufferLength);
		//Writing a dummy header
		buffer.write("key", offset, 3);
		offset += 3;
		//Writing the prime field
		buffer.writeUInt16BE(keyPair.primeField.length, offset);
		offset += 2;
		buffer.write(keyPair.primeField, offset, keyPair.primeField.length);
		offset += keyPair.primeField.length;
		//Writing the divider
		buffer.writeUInt16BE(keyPair.divider.length, offset);
		offset += 2;
		buffer.write(keyPair.divider, offset, keyPair.divider.length);
		offset += keyPair.divider.length;
		//Writing the base
		buffer.writeUInt16BE(keyPair.base.length, offset);
		offset += 2;
		buffer.write(keyPair.base, offset, keyPair.base.length);
		offset += keyPair.base.length;
		//Writing the public element
		buffer.writeUInt16BE(keyPair.publicElement.length, offset);
		offset += 2;
		buffer.write(keyPair.publicElement, offset, keyPair.publicElement.length);
		offset += keyPair.publicElement.length;
		//Writing the private key
		buffer.writeUInt16BE(keyPair.privateKey.length, offset);
		offset += 2;
		buffer.write(keyPair.privateKey, offset, keyPair.privateKey.length);
		offset += keyPair.privateKey.length;
	}
	fs.writeFileSync(filename, buffer);
}