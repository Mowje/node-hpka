/*
* Types of testing to do:
*
* - Per key type, general usage (clients & servers)
* - Security edge cases (server-side, mostly)
* - API behaviour
*/

var hpka = require('hpka');

var availableAlgos = hpka.supportedAlgorithms();

function testKeyType(keyType){
	if (typeof keyType != 'string') throw new TypeError('keyType must be a string');

	var keyTypeAvail = false;
	for (var i = 0; i < availableAlgos.length; i++) if (availableAlgos[i] == keyType) keyTypeAvail = true;
	if (!keyTypeAvail) throw new TypeError(keyType + ' keys are unavailable');

	
}
