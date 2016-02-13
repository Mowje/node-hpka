/**
* Extract public key from an HPKAReq object
* @param {Object} HPKAReq - an HPKAReq object, from which the public key will be extracted
* @returns {Object} - the extracted public key object
*/
exports.getPublicKeyFromHPKAReq = function(HPKAReq){
	//Checking that HPKAReq object is correctly formed
	var reqObj = {};
	if (!HPKAReq.keyType) throw new TypeError('Invalid HPKAReq obejct on getPubKeyObject method');
	reqObj.keyType = HPKAReq.keyType;
	if (HPKAReq.keyType == 'ecdsa'){ //ECDSA case
		if (!(HPKAReq.curveName && HPKAReq.point && HPKAReq.point.x && HPKAReq.point.y)) throw new TypeError('Malformed ECDSA request');
		reqObj.curveName = HPKAReq.curveName;
		reqObj.point = {x: HPKAReq.point.x, y: HPKAReq.point.y};
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
};

/**
* Check public key equalities. Useful for loginCheck functions in servers
* @param {Object} pk1 - public key 1
* @param {Object} pk2 - public key 2
* @returns {Boolean} - true if provided public keys are equal. False otherwise
*/
exports.checkPublicKeyEquality = function(pk1, pk2){
	if (!(typeof pk1 == 'object' && typeof pk2 == 'object')) throw new TypeError('Parameters must be objects');
	if (pk1.keyType != pk2.keyType) return false;
	if (pk1.keyType == "ecdsa"){
		//console.log('Common type : ecdsa');
		if (pk1.curveName != pk2.curveName) return false;
		if (pk1.point.x != pk2.point.x) return false;
		if (pk1.point.y != pk2.point.y) return false;
	} else if (pk1.keyType == "rsa"){
		//console.log('Common type : rsa');
		if (pk1.modulus != pk2.modulus) return false;
		if (pk1.publicExponent != pk2.publicExponent) return false;
	} else if (pk1.keyType == "dsa"){
		//console.log('Common type : dsa');
		if (pk1.primeField != pk2.primeField) return false;
		if (pk1.divider != pk2.divider) return false;
		if (pk1.base != pk2.base) return false;
		if (pk1.publicElement != pk2.publicElement) return false;
	} else if (pk1.keyType == 'ed25519'){
		//console.log('Common type : ed25519');
		if (pk1.publicKey != pk2.publicKey) return false;
	} else throw new TypeError('Invalid keyType');
	return true;
};
