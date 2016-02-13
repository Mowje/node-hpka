var publicKeyUtils = require('./publicKeyUtils');

/*
* We trust that the provided reqElements are the usual HPKAReq you would expect.
* Hence, all this method makes is a read-only deep copy of the reqElements object
*/
function HPKAReq(reqElements){
	if (typeof reqElements != 'object') throw new TypeError('What the hell are you doing???');
	var reqElementsList = Object.keys(reqElements);
	var self = this;
	var keyType = reqElements.keyType;

	if (!keyType) throw new TypeError('What the hell are you doing???');
	reqElementsList.forEach(function(currentElem){
		var currentValue = reqElements[currentElem];
		if (currentElem == 'point') currentValue = {x: currentValue.x, y: currentValue.y}; //Deep copy of point property, in ECDSA case

		var propertyAttributes = {
			writable: false,
			enumerable: true,
			value: currentValue
		};

		Object.defineProperty(self, currentElem, propertyAttributes);
	});
}

HPKAReq.prototype.getPublicKey = function() {
	return publicKeyUtils.getPublicKeyFromHPKAReq(this);
};

HPKAReq.prototype.checkPublicKeyEqualityWith = function(otherPublicKey){
	return publicKeyUtils.checkPublicKeyEquality(this, otherPublicKey);
};

module.exports = HPKAReq;
