var path = require('path'), 
  nacl = require('tweetnacl/nacl-fast'),
  Base58 = require(path.join(__dirname, 'base58')),
  BLAKE2s = require('blake2s-js'),
  keySize = 32;


module.exports = {

  /**
   * Validates if a string is a proper public key.
   * @param {string} publicKeyString
   * @returns {boolean} true if valid
   */
  validatePublicKeyString: function(publicKeyString) {
    var base58Match = new RegExp('^[1-9ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$')
    if ((publicKeyString.length > 55) || (publicKeyString.length < 40)) {
      return false;
    }
    if (!base58Match.test(publicKeyString)) {
      return false;
    }

    var bytes = Base58.decode(publicKeyString);
    if (bytes.length !== 33) {
      return false;
    }

    var hash = new BLAKE2s(1);
    bytes = new Uint8Array(bytes);
    hash.update(bytes.subarray(0, 32));
    if (hash.digest()[0] !== bytes[32]) {
      return false;
    }
    return true
  },

  /**
   * Generates public key in string representation from key bytes
   * @param {Uint8Array} publicKeyBytes
   * @returns {string} Base58 encoded key
   */
  getPublicKeyString: function (publicKeyBytes) {
    var key = new Uint8Array(keySize + 1);
    for (var i = 0; i < publicKeyBytes.length; i++)
      key[i] = publicKeyBytes[i];

    var hash = new BLAKE2s(1);
    hash.update(publicKeyBytes);
    key[keySize] = hash.digest()[0];

    return Base58.encode(key);
  },

   /**
   * Extracts byte array from public key string representation
   * @param {string} publicKey
   * @return {Uint8Array} publicKeyBytes
   */
  getPublicKeyBytes: function (publicKeyString) {
    return Base58.decode(publicKeyString).subarray(0, keySize);
  },

  /**
   * Decrypts authentication token
   * @param {{ephemeralServerPublicKey:string, token:string, nonce:string}} data - authToken data as received from server.
   * @param {object} keyPair
   * @returns {object|Boolean} decrypted token
   */
  decryptToken: function (data, keyPair) {
    if (data.hasOwnProperty('error')) {
      console.error(data.error);
      return false;
    }

    var dToken = nacl.box.open(
      nacl.util.decodeBase64(data.token),
      nacl.util.decodeBase64(data.nonce),
      this.getPublicKeyBytes(data.ephemeralServerPublicKey),
      keyPair.secretKey
    );

    if (dToken && dToken.length === 0x20 && dToken[0] === 0x41 && dToken[1] === 0x54)
      return nacl.util.encodeBase64(dToken);

    return false;
  }
  
}