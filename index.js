'use strict';

const express = require('express');
const schedule = require('node-schedule');
const _ = require('lodash');
const crypto = require('./lib/peerio_crypto_mod');
const port = process.env.PORT || 3333;
const app = express();
const Base58 = require('./lib/base58');
const nacl = require('tweetnacl/nacl-fast');
nacl.util = require('tweetnacl-util');
const bodyParser = require('body-parser');

const redis = require('redis').createClient();
const keys = {};
const keyPair = nacl.box.keyPair();
const router = express.Router();

app.listen(port);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use('/api', router);
keys.public = crypto.getPublicKeyString(keyPair.publicKey);
keys.private = nacl.util.encodeBase64(keyPair.secretKey);


const  encryptToken = (token, userPublicKeyString) => {
	const nonce = nacl.randomBytes(24);
    const userBytes = new Uint8Array(Base58.decode(userPublicKeyString));
    const serverEphemeralSecret = nacl.util.decodeBase64(keys.private);
    const encrypted_token = nacl.box(
		nacl.util.decodeBase64(token),
		nonce,
		userBytes.subarray(0, 32),
		serverEphemeralSecret
	);
	return {
		token: nacl.util.encodeBase64(encrypted_token),
		nonce: nacl.util.encodeBase64(nonce),
		ephemeralServerPublicKey: keys.public
	}
};

const generateToken = () => {
	const token = new Uint8Array(32);
	token[0] = 0x41;
	token[1] = 0x54;
	token.set(nacl.randomBytes(30), 2);
	return nacl.util.encodeBase64(token);
};

// track
router.use((req, res, next) => {
    if (req.params.publicKey) {
    	redis.incr('usage:' + publicKey)
    }
    next(); 
});

router.get('/generate/:publicKey', (req, res) => {
	const publicKey = req.params.publicKey;
    const tokens = _.times(10).map(() => generateToken());
    tokens.forEach(t => redis.set(t, publicKey));
    const encryptedTokens = tokens.map(t => encryptToken(t, publicKey));
	res.status(200).json({
		tokens: encryptedTokens
	})
});

// check validity of a token
router.post('/tokens/:token', function(req, res) {
      	const decryptedToken = req.params.token;
      	const publicKey = req.body.publicKey;

        redis.get(decryptedToken, function(err, val) {
        	if (val && val.toString() === publicKey) {
        		res.status(200).json({ status: 'ok' });
        	} else {
        		res.status(500).json({ error: 'error' });
        	}
        	redis.del(decryptedToken);
        })
});

schedule.scheduleJob('* 3 * * *', function() {
	console.log('change server\'s ephemeral keypair');

	keys.public = crypto.getPublicKeyString(keyPair.publicKey);
	keys.private = nacl.util.encodeBase64(keyPair.secretKey);
});
