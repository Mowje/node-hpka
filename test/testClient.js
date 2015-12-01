var http = require('http');
var fs = require('fs');
var assert = require('assert');
var hpka = require('../hpka');
var cryptopp, sodium;
var Buffer = require('buffer').Buffer;
var FormData = require('form-data');

//The test user's name and password/passphrase
//Note : the password is only used with Ed25519 because its keyring allows it
//The keyring from node-cryptopp doesn't support yet password protection for key files
var testUsername = 'test';
var testPassword = 'password';
var keyType;

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
};

exports.setup = function(keyPath){
	var retVal = hpka.createClientKey(keyType, testKeyOptions[keyType], keyPath, password, true);
	
};

//Write the different test cases that must be executed for each key type. Will be called from index.js
exports.unauthenticatedReq = function(cb){

};

exports.registrationReq = function(cb){

};

exports.authenticatedReq = function(cb, withForm){

};

exports.deletionReq = function(cb){

};

exports.keyRotationReq = function(cb){

};

exports.spoofedSignatureReq = function(cb){

};

exports.spoofedUsernameReq = function(withUsername){

};

exports.sessionAgreementReq = function(cb){

};

exports.sessionRevocationReq = function(cb){

};

exports.sessionAuthenticatedReq = function(cb){

};
