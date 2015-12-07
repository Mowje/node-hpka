/*
* Types of testing to do:
*
* - Per key type, general usage (clients & servers)
* - Security edge cases (server-side, mostly)
* - API behaviour
*/

var hpka = require('hpka');

var testClient = require('./testClient');
var testServer = require('./testServer');

var cbLoc = '#cbhere#';

var yell = process.argv.length > 2 && process.argv[2] == 'verbose';

var serverSettings = {
	host: 'localhost',
	port: 2500,
	method: 'GET',
	path: '/'
};

var availableAlgos = hpka.supportedAlgorithms();

var testCases = [];
var testCaseIndex = 0;

var currentTestCase = {strictMode: false, useExpress: false, disallowSessions: false};
for (var i = 0; i < availableAlgos.length; i++){
	var state = 0;
	currentTestCase.keyType = availableAlgos[i];

	//Generating the parameters for all the test cases, for each key type, and storing them in the testCases array
	do {
		testCases.push(clone(currentTestCase));
		state = currentTestCase.strictMode * 4 + currentTestCase.useExpress * 2 + currentTestCase.disallowSessions;
		state = (state + 1) % 8;
		currentTestCase.strictMode = (state & 0x04) == 4;
		currentTestCase.useExpress = (state & 0x02) == 2;
		currentTestCase.disallowSessions = (state & 0x01) == 1;
	} while (state != 0);
}

function performTests(keyType, strictMode, useExpress, disallowSessions, next){
	if (typeof keyType != 'string') throw new TypeError('keyType must be a string');
	if (typeof next != 'function') throw new TypeError('next must be a function');

	var keyTypeAvail = false;
	for (var i = 0; i < availableAlgos.length; i++) if (availableAlgos[i] == keyType) keyTypeAvail = true;
	if (!keyTypeAvail) throw new TypeError(keyType + ' keys are unavailable');

	log('---------------NEW TEST CASE---------------');
	log('Current test case');
	log('Key type: ' + keyType);
	log('Strict mode: ' + strictMode);
	log('Use express server: ' + useExpress);
	log('-------------------------------------------');

	function setupServer(N){
		testServer.clear();
		testServer.setServerPort(serverSettings.port);
		testServer.setup(strictMode, disallowSessions, useExpress);

		log('Starting server');
		testServer.start(function(){
			log('Server has been started');
			N();
		});
	}

	function setupClient(N){
		testClient.setKeyType(keyType);
		testClient.setServerSettings(serverSettings);
		testClient.setup();

		N();
	}

	function testNormalRequests(N){
		var calls = [
			{f: testClient.unauthenticatedReq, a: [cbLoc]}, //Testing an unauthenticated request
			{f: testClient.registrationReq, a: [cbLoc]}, //Registration
			{f: testClient.authenticatedReq, a: [cbLoc]} //Authenticated request
		];

		chainAsyncFunctions(calls, N);
	}

	function testSpoofedRequests(N){
		var calls = [
			{f: testClient.spoofedSignatureReq, a: [cbLoc, strictMode]},
			{f: testClient.spoofedHostReq, a: [cbLoc, strictMode]},
			{f: testClient.spoofedUsernameReq, a: ['test2', cbLoc, strictMode]}
		];

		if (!disallowSessions) calls.push({f: testClient.spoofedSessionReq, a: ['test2', cbLoc]});

		chainAsyncFunctions(calls, N);
	}

	function testMalformedRequests(N){
		var calls = [
			{f: testClient.malformedReq, a: [cbLoc, strictMode]},
			{f: testClient.malformedReqNonBase64, a: [cbLoc, strictMode]}
		];

		if (!disallowSessions){
			calls.push({f: testClient.malformedSessionReq, a: [cbLoc]});
			calls.push({f: testClient.malformedSessionReqNonBase64, a: [cbLoc]});
		}

		chainAsyncFunctions(calls, N);
	}
}

function doTestCase(){
	var nextTestCase = testCases[testCaseIndex];

	performTests(nextTestCase.keyType, nextTestCase.strictMode, nextTestCase.useExpress, nextTestCase.disallowSessions, function(){
		testCaseIndex++;
		if (testCaseIndex == testCases.length){ //All test cases have been executed
			log('HPKA testing (client and server) completed with success');
			process.exit(0);
		} else doTestCase(); //Go to next test case
	});
}

function chainAsyncFunctions(functionsList, callback){
	var fIndex = 0;

	function doOne(){
		var theFunction = functionsList[fIndex].f;
		var theArguments = functionsList[fIndex].a.slice();
		insertCallbackInArguments(theArguments, next, true);

		theFunction.apply(this, theArguments);
	}

	function next(){
		fIndex++;
		if (fIndex == functionsList.length) callback();
		else { //Trying to limit the callstack size
			if (fIndex % 100 == 0) setTimeout(doOne, 0);
			else doOne();
		}
	}

	doOne();

}

function insertCallbackInArguments(ar, cb, assertFound){
	for (var i = 0; i < ar.length; i++){
		if (ar[i] == cbLoc){
			ar[i] = cb;
			return;
		}
	}
	if (assertFound) throw new Error('#cbhere# cannot be found in array: ' + JSON.stringify(ar));
}

function log(m){
	if (yell) console.log(m);
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
