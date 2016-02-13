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
	if (pk1.keyType.toLowerCase() != pk2.keyType.toLowerCase()) return false;

	var pkType = pk1.keyType.toLowerCase();

	if (pkType == "ecdsa"){
		//console.log('Common type : ecdsa');
		if (pk1.curveName.toLowerCase() != pk2.curveName.toLowerCase()) return false;
		if (pk1.point.x.toLowerCase() != pk2.point.x.toLowerCase()) return false;
		if (pk1.point.y.toLowerCase() != pk2.point.y.toLowerCase()) return false;
	} else if (pkType == "rsa"){
		//console.log('Common type : rsa');
		if (pk1.modulus.toLowerCase() != pk2.modulus.toLowerCase()) return false;
		if (pk1.publicExponent.toLowerCase() != pk2.publicExponent.toLowerCase()) return false;
	} else if (pkType == "dsa"){
		//console.log('Common type : dsa');
		if (pk1.primeField.toLowerCase() != pk2.primeField.toLowerCase()) return false;
		if (pk1.divider.toLowerCase() != pk2.divider.toLowerCase()) return false;
		if (pk1.base.toLowerCase() != pk2.base.toLowerCase()) return false;
		if (pk1.publicElement.toLowerCase() != pk2.publicElement.toLowerCase()) return false;
	} else if (pkType == 'ed25519'){
		//console.log('Common type : ed25519');
		if (pk1.publicKey.toLowerCase() != pk2.publicKey.toLowerCase()) return false;
	} else throw new TypeError('Invalid keyType');
	return true;
};
