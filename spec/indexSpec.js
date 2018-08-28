'use strict';

const request = require('request');
const crypto = require('../lib/peerio_crypto_mod');
const nacl = require('tweetnacl/nacl-fast');
nacl.util = require('tweetnacl-util');
const port = process.env.PORT || 3333;

let tokens,
	serverPublicKey,
	myKeyPair = nacl.box.keyPair();

describe("Generating tokens", () => {
	it("should respond with 10 encrypted tokens", done => {
		const myPublicKeyString = crypto.getPublicKeyString(myKeyPair.publicKey);

	  	request(`http://localhost:${port}/api/generate/${myPublicKeyString}`, (error, response, body) =>{
		  	var b = JSON.parse(response.body);
		  	tokens = b.tokens; 
		  	serverPublicKey = b.ephemeralServerPublicKey;
		    expect(response.statusCode).toEqual(200);
		    expect(tokens.length).toEqual(10);
		    done();
	  	});
	});
});

describe("Validating tokens", () => {
	it("should return an error for an unknown token", function(done) {
		const publicKey = crypto.getPublicKeyString(myKeyPair.publicKey);

		request(
		    {
                uri: `http://localhost:${port}/api/tokens/garbage`,
                method: 'post',
                json: true,
                body: { publicKey }
            },
            (error, response, body) => {
                expect(response.statusCode).toEqual(500);
                done();
		    }
		);
	});

	it("should return an error for a known token and incorrect user", function(done) {
		const validDecryptedToken = crypto.decryptToken(tokens[0], myKeyPair);

		request({ uri: `http://localhost:${port}/api/tokens/${validDecryptedToken}`, method: 'post', json: true, body: { publicKey: 'garbage' } }, (error, response, body) => {
		    expect(response.statusCode).toEqual(500);
		    done();
	  	});	
	});

	it("should return an error for an unknown token", function(done) {
        const publicKey = crypto.getPublicKeyString(myKeyPair.publicKey);

        request(
            {
                uri: `http://localhost:${port}/api/tokens/garbage`,
                method: 'post',
                json: true,
                body: { publicKey }
            },
            (error, response, body) => {
                expect(response.statusCode).toEqual(500);
                done();
            }
        );
	})
});