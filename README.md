# node-hpka
------------------------------------------------------------

A [Node.js](http://nodejs.org) implementation of the [HPKA protocol](https://github.com/Mowje/hpka). Acts as an [expressjs](https://github.com/visionmedia/express) middleware or standard [HTTP](http://nodejs.org/api/http.html)/[HTTPS](http://nodejs.org/api/https.html) middlware. It also has an HPKA client object.

## Installation

To install the latest stable version node-hpka, simply run from app's root folder :
```
npm install hpka
```

## Dependencies

As of v0.2.0, this modules doesn't have mandatory dependencies (ie, they are not listed in package.json). It depends on which key types you want to support. You need :

* [cryptopp](https://github.com/Mowje/node-cryptopp.git) if you want to support requests with ECDSA, RSA or DSA keys
* [sodium](https://github.com/Mowje/node-sodium.git) if you want to support requests with Ed25519 keys

These dependencies don't necessarily need to be installed locally for the module, but [could be used in a higher level of the "node_modules" folder](http://nodejs.org/api/modules.html#modules_loading_from_node_modules_folders). Note that for sodium, you have to use [our fork](https://github.com/Mowje/node-sodium) of the module and not the [original one](https://github.com/paixaop/node-sodium). This is due to the fact that we added a [KeyRing](https://github.com/Mowje/node-sodium#use-the-keyring) feature in our fork that did not exist in the original module.

## How to install dependencies

For `cryptopp`:

	npm install git+https://github.com/Mowje/node-cryptopp.git --save

For `sodium`:

	npm install git+https://github.com/Mowje/node-sodium.git --save

As mentionned earlier, these modules can be installed either as a dependency of this module (ie, going to the folder containing the HPKA code and installing the dependencies there) or they could installed as a "normal" dependency of your application (probably the best option in order to dodge potential deployment issues with missing dependencies).

## How do the middlwares work?

The middlewares will help you parsing the HPKA requests and verifying the signatures of the payloads. Then, it's your job to check that the usernames and public keys sent to the server match to the records you already have (through DB queries and what not).

When authentication succeeds, then the `req` objects recieves the following attributes (doesn't matter whether you use the express middleware or the standard http stack) :  
* `.username` : the username parsed in from the request
* `.hpkareq` : the [HPKA-Req object](https://github.com/Mowje/node-hpka#hpkareq-object) parsed from the request

**Please note that in order to avoid replay attacks, your application MUST check that the host/hostname of the request is valid. If you don't, in the context of a distributed network of servers, a server can impersonate one of your users by sending the requests he receives (where the signatures takes the attacker's hostname into account, and where you don't check that the requests you receive are signed with your hostname; the attacking server can then request from the target server the same resource that the user requested from the attacking server).**

## Usage

**NOTE:** API has changed as of v0.2.0. Afterwards, there are no API breaks (v0.3.x included, aside the removal of an initially internal method called `buildPayload`)

The module exposes 7 methods :

`hpka.supportedAlgorithms()` : Returns an array containing the signature algorithms supported, depending on what crypto modules are installed

### Server methods

`hpka.expressMiddleware(loginCheck, registration, userDeletion, keyRotation, strict)`: the Expressjs middleware builder :

* loginCheck(HPKAReq, req, res, callback(Boolean)) :
	* HPKAReq : the HPKAReq object, as descibed below
	* req : the [expressjs req](http://expressjs.com/api.html#req.params) object, in case you want to you know what was the route requested by the client
	* res : the [expressjs res](http://expressjs.com/api.html#res.status) object, in case you want to show some error pages and what not
	* callback(isValid) : function to be called if you didn't respond to the client. isValid should be a boolean indicating whether the user is registered and the public key is valid or not. If this is used, the sever will respond using the route corresponding to the HTTP request defined in your express app.
* registration(HPKAReq, req, res, next) :
	* HPKAReq : the HPKAReq object, as described below
	* req : the [expressjs req](http://expressjs.com/api.html#req.params) object, in case you want to you know what was the route requested by the client.
	* res : the [expressjs res](http://expressjs.com/api.html#res.status) object, to show a welcome page (or back to the site's homepage).
	* next : the method that will route the request to the corresponding route handler. You can call this method in case you want to use the default route of the request after registration, or you can use the `res` object to respond to the client. The choice is yours.
* userDeletion(HPKAReq, req, res) :
	* HPKAReq: the HPKAReq object, as described below
	* req : the [expressjs req](http://expressjs.com/api.html#req.params) object, in case you want to you know what was the route requested by the client.
	* res : the [expressjs res](http://expressjs.com/api.html#res.status) object, allowing you confirm user deletion or send an error message
* keyRotation(HPKAReq, rotationReq, req, res, next) :
	* HPKAReq: the HPKAReq object, as described below, with the user's actual public key. **NOTE :** you have to check that it is really his/her actual public key
	* rotationReq : an HPKAReq object, containing this time the new public key
	* req : the [expressjs req](http://expressjs.com/api.html#req.params) object, in case you want to you know what was the route requested by the client
	* res : the [expressjs res](http://expressjs.com/api.html#res.status) object, allowing you to send a message to the client and what not
	* next : the method that will route the request to the corresponding route handler. You can call this method in case you want to use the default route of the request after key rotation, or you can use the `res` object to respond to the client. The choice is yours.
* strict : must be a boolean when defined. Defines whether it shows error message when there is a problem (if true), or just renders the page while ignoring the authentication request (if false; like if it was normal HTTP request). Note that this applies to all error types except a "unavailable username" error.

Note that :

* you must use either ```res``` or ```callback``` in loginCheck to send a response to the client
* but you **must** use ```res``` in registration to send a response to the client


`hpka.httpMiddlware(requestHandler, loginCheck, registartion, userDeletion, keyRotation, strict)`: middleware building function for the standard [HTTP](http://nodejs.org/api/http.html) and [HTTPS](http://nodejs.org/api/https.html) libraries. The result of this function should be used as the ```requestHandler``` in the ```createServer``` methods of these libraries. The function receives the following parameters :

* requestHandler(req, res) : the request handler you would normally put in the ```createServer``` methods of the 2 default HTTP stacks
* loginCheck(HPKAReq, res, callback(Boolean)) :
	* HPKAReq : the HPKAReq object, [as descibed below](https://github.com/Mowje/node-hpka#hpkareq-object)
	* req : the [request](http://nodejs.org/api/http.html#http_http_incomingmessage) object, in case you want to know which path was requested by the user for example
	* res : the [response](http://nodejs.org/api/http.html#http_class_http_serverresponse) object, in case you want to show some error pages or something
	* callback(isValid) : function to be called if you didn't respond to the client. isValid should be a boolean indicating whether the user is registered and the public key is valid or not
* registration(HPKAReq, req, res, next) :
	* HPKAReq : the HPKAReq object, [as described below](https://github.com/Mowje/node-hpka#hpkareq-object)
	* req : the [request](http://nodejs.org/api/http.html#http_http_incomingmessage) object, in case you want to know which path was requested by the user for example
	* res : the [response](http://nodejs.org/api/http.html#http_class_http_serverresponse) object, to show a welcome page (or back to the site's homepage).
	* next : the method that will route the request to `requestHandler`. You can call this method in case you want to use the default route of the request after registration, or you can use the `res` object to respond to the client. The choice is yours.
* userDeletion(HPKAReq, req, res), called when a user wants to delete his/her account :
	* HPKAReq : the HPKAReq object, [as described below](https://github.com/Mowje/node-hpka#hpkareq-object)
	* req : the [request](http://nodejs.org/api/http.html#http_http_incomingmessage) object, in case you want to know which path was requested by the user for example
	* res : the [response](http://nodejs.org/api/http.html#http_class_http_serverresponse) object, allowing you to respond to the client or sending an error message,...
* keyRotation(HPKAReq, rotationReq, req, res), called when a user wants to change his authentication key :
	* HPKAReq: the HPKAReq object, [as described below](https://github.com/Mowje/node-hpka#hpkareq-object), with the user's actual public key. **NOTE :** you have to check that it is really his/her actual public key
	* rotationReq : an [HPKAReq object](https://github.com/Mowje/node-hpka#hpkareq-object), containing this time the new public key
	* req : the [request](http://nodejs.org/api/http.html#http_http_incomingmessage) object, in case you want to know which path was requested by the user for example
	* res : the [response](http://nodejs.org/api/http.html#http_class_http_serverresponse) object, allowing you to send a message to the client and what not.
	* next : the method that will route the request to `requestHandler`. You can call this method in case you want to use the default route of the request after key rotation, or you can use the `res` object to respond to the client. The choice is yours.
* strict : must be a boolean when defined. Defines whether it shows error message when there is a problem (if true), or just renders the page while ignoring the authentication request (if false; like if it was a normal HTTP request). Note that this applies to all error types except an "unavailable username" error.

### Client methods

`hpka.client(keyFilename|keyRing, username, password)`:  
Client building method. Two ways of using it:
* In case a file path is given, loads the keypair from the given filename using a [cryptopp KeyRing](https://github.com/Mowje/node-cryptopp#keyring) or [sodium KeyRing](https://github.com/Mowje/node-sodium/blob/master/docs/keyring-api.md), depending on the keyType. The username given to this method will be the one used in the HTTP requests generated by this client. The password parameter can be added when using an Ed25519 key; and it will be used to decrypt the keyfile.
* In case a `cryptopp.KeyRing` or `sodium.KeyRing` is given, the key held in that KeyRing is used to sign the requests (that will contain the passed username as always). The password parameter is simply ignored in this case. An exception is thrown if the passed KeyRing instance has no key loaded into it.

The returned `client` object have the following method(s) :

* clear() : the clear the internal KeyRing object. This method MUST be called when you finish using the `client` object.
* request(options, [body], callback, [errorHandler]), send an authenticated HTTP request :
	* options : the [HTTP](http://nodejs.org/api/http.html)/[HTTPS](http://nodejs.org/api/https.html) options object. Note that if you want to use https, you must set `options.protocol = 'https'`; otherwise, http is used
	* body : body of the request. Optional. Either a buffer or a string or a [FormData](https://github.com/felixge/node-form-data) object
	* callback : method that will be called once the request is sent. The callback will have the [response](http://nodejs.org/api/http.html#http_http_incomingmessage) object as unique parameter
	* errorHandler : optional error handler function
* registerUser(options, callback, [errorHandler], [body]), register the user on the server :
	* options : the [HTTP](http://nodejs.org/api/http.html)/[HTTPS](http://nodejs.org/api/https.html) options object. Note that if you want to use https, you must set `options.protocol = 'https'`; otherwise, http is used
	* callback : method that will be called once the request is sent. The callback will have the [response](http://nodejs.org/api/http.html#http_http_incomingmessage) object as unique parameter
	* errorHandler : optional error handler function
	* body : body of the request. Optional. Either a buffer or a string or a [FormData](https://github.com/felixge/node-form-data) object
* deleteUser(options, callback, [errorHandler]), delete the user's account :
	* options : the [HTTP](http://nodejs.org/api/http.html)/[HTTPS](http://nodejs.org/api/https.html) options object. Note that if you want to use https, you must set `options.protocol = 'https'`; otherwise, http is used
	* callback : method that will be called once the request is sent. The callback will have the [response](http://nodejs.org/api/http.html#http_http_incomingmessage) object as unique parameter
	* errorHandler : optional error handler function
* rotateKeys(options, newKeyPath, callback, [errorHandler], [body]), key rotation request (ie, key change/swap) :
	* options : the [HTTP](http://nodejs.org/api/http.html)/[HTTPS](http://nodejs.org/api/https.html) options object. Note that if you want to use https, you must set `options.protocol = 'https'`; otherwise, http is used
	* newKeyPath : path where the new key file is stored. That file could either be created with `hpka.createClientKey()` or [cryptopp.KeyRing](https://github.com/Mowje/node-cryptopp#keyring).
	* callback : method that will be called once the request is sent. The callback will have the [response](http://nodejs.org/api/http.html#http_http_incomingmessage) object as unique parameter
	* errorHandler : optional error handler function
	* body : body of the request. Optional. Either a buffer or a string or a [FormData](https://github.com/felixge/node-form-data) object
* setHttpMod(httpRef), set the http module you want to use :
	* httpRef : the http module you want to use, overriding the [default one](http://nodejs.org/api/http.html). To go back to the default module, call the method again with no parameter. Example use case : using HPKA with Tor, as explained below.
* setHttpsMod(httpsRef), set the https module you want to use :
	* httpsRef : the https module you want to use, overriding the [default one](https://nodejs.org/api/https.html). To go back to the default module, call the method again with no parameter. Example use case : using HPKA with Tor, as explained below.

`hpka.createClientKey(keyType, options, filename, password, doNotReturn)`: creates a new keypair file. Returns the underlying KeyRing object when finished
* keyType : must be either 'ecdsa', 'rsa', 'dsa' or 'ed25519'
* options : the curve name for ecdsa, the key size for RSA and RSA.
* filename : path where the key file should be stored.
* password : password that will be used to encrypt the newly generated key, only for ed25519 keys
* doNotReturn : if defined, then the KeyRing object is cleared from memory and not returned. I recommend the use of this parameter in case you're not going to use the key right away / ignoring the returned KeyRing object

`hpka.changeClientKeyPassword(keyFilename, oldPassword, newPassword)`: Change the password used to encrypt a given key file. **Only for Ed25519 key files!**  
* keyFilename : string, absolute or relative path to the key file
* oldPassword : string or buffer, the current key file password
* newPassword : string or buffer, the new key file password

`hpka.buildPayload(keyRing, username, actionType, hostnameAndPath, httpVerb, callback)`:
Build (asynchronously) a client HPKA payload with the given parameters:  
* keyRing : a KeyRing instance from [sodium](https://github.com/Mowje/node-sodium.git) or [cryptopp](https://github.com/Mowje/node-cryptopp.git)
* username : the user's name (a string)
* actionType : a byte, indicating the action type, as defined in the [HPKA spec](https://github.com/Mowje/hpka#hpka-req-protocol)
* hostnameAndPath : the hostname and path of the request (with request parameters included, as they are part of it in HTTP), concatenated
* httpVerb : the HTTP verb used in the request (as a string). Most common ones are : 'get', 'post', 'put', 'delete'
* callback : a function, that will recieve as parameters the (req, signature) encoded duplet (for the HPKA-Req and HPKA-Signature headers respectively)

## Using the client with Tor (or any SOCKS5 proxy server)

I see 2 ways of doing this:

1. When doing a HPKA request, set `options.agent` with the agent from [Mattcg](https://github.com/mattcg)'s [socks5-http-client](https://github.com/mattcg/socks5-http-client) and [socks5-https-client](https://github.com/mattcg/socks5-https-client) as you would do when using [request](https://github.com/mattcg/socks5-http-client#using-with-request)
2. Use the `setHttpMod()` and `setHttpsMod()` methods to override the default http/https modules with instances from the 2 socks modules mentionned above (not agent instances, but just `require('socks5-http-client')` and `require('socks5-https-client')` and you would pass the `socksHost` and `socksPort` parameters as attributes in the `options` parameter object)

Note also that if you want to host a server with HPKA behind a hidden service, you can simply use something like [node-ths](https://github.com/Mowje/node-ths).

## HPKAReq object

The HPKAReq object is the result of parsing the [HPKA-Req field](https://github.com/Mowje/hpka#hpka-req-protocol). I will here just list its attributes :

* username: a string
* actionType : a number, as defined in the spec
* timeStamp : the date&time at which the payload was built and signed. UTC Unix Epoch (number of **seconds** since 1-1-1970 00:00:00 UTC)
* err : a string, defined only if an error occured. As of now, it is only defined if a request with an ECDSA, RSA or DSA key comes in and `cryptopp` is not insalled (Same thing for Ed25519 and `sodium` respectively)
* errcode : is defined when `.err` is defined. The HPKA Error code corresponding to the message in `.err`.
* keyType : a string (either "ecdsa", "rsa", "dsa" or "ed25519")
* In case of keyType == "ecdsa"
	* point : the public ECDSA point, which has :
		* x : the x coordinate, as a hex string
		* y : the y coordinate, as a hex string
* In case of keyType == "rsa"
	* modulus : a hex string of the RSA modulus
	* publicExponent : a hex string of the RSA public exponent
* In case of keyType == "dsa"
	* primeField : a hex string of the DSA prime field
	* divider : a hex string of the DSA divider
	* base : a hex string of the DSA base
	* publicElement : a hex string of the public DSA element
* In case of keyType == "ed25519"
	* publicKey : a hex encoded string of the public key

## Example

For more detailed examples, have a look at [test.js](https://github.com/Mowje/node-hpka/blob/master/test.js) or [expressTest.js](https://github.com/Mowje/node-hpka/blob/master/expressTest.js).

```js
var hpkaBuilder = require('hpka');
var hpkaMiddleware = hpkaBuilder.expressMiddlware(
	function(HPKAReq, req, res, callback){ //Login check
		//If there isn't a user with the username as in HPKAReq, then render error or warning page and return
		//If there is a user with username and publickey as in HPKAReq, then callback(true)
		//Else callback(false)
	},
	function(HPKAReq, req, res, next){ //User registration
		//Check that the username is not already used
		//Save the details from HPKAReq
		//Use res to show welcome page or call next(); to use the route by default for this request
	},
	function(HPKAReq, req, res){ //Account deletion
		//Check that the user exists and has the given public key
		//Delete the user
		//Respond using the res object
	},
	function(HPKAReq, RotationReq, req, res, next){ //Key rotation
		//Check that the user exists and has the given public key
		//Update the public key for the user with the one in RotationReq
		//Respond using the res object or call next(); to use the route by default for this request
	},
	true
);
```

## Where to load the expressjs middleware?

To load express middlwares, you have to call the ```app.use(middlware)``` method. The thing is that, as far as I understand, the loading order of middlwares impact the order of middlware execution when a request comes to the server. It seems it is "first loaded, first executed". Also it seems that my middlware isn't called when it is loaded after ```app.router```. In addition, if you want to serve public static folders (without authentication), you should take that into account too. So here is how I loaded the hpka middleware in my example application :

```js
app.use(someMiddlware)
app.use(someOtherMiddlware)
//Whatever other middlewares you want to load…
app.use(somePublicFolder)
app.use(hpkaMiddlware)
app.use(app.router)
```

## License

This module is released under MIT license.
