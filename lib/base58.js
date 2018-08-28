var Base58 = {};

(function () {

  var BASE = 58;
  var BITS_PER_DIGIT = Math.log(BASE) / Math.log(2);
  var ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  var ALPHABET_MAP = {};

  for (var i = 0; i < ALPHABET.length; i++) {
    ALPHABET_MAP[ALPHABET.charAt(i)] = i;
  }

  function decodedLen(n) {
    return Math.floor(n * BITS_PER_DIGIT / 8);
  }

  function maxEncodedLen(n) {
    return Math.ceil(n / BITS_PER_DIGIT);
  }

  Base58.encode = function (buffer) {
    if (buffer.length === 0) return '';

    var i, j, digits = [0];
    for (i = 0; i < buffer.length; i++) {
      for (j = 0; j < digits.length; j++) digits[j] <<= 8;

      digits[0] += buffer[i];

      var carry = 0;
      for (j = 0; j < digits.length; ++j) {
        digits[j] += carry;
        carry = (digits[j] / BASE) | 0;
        digits[j] %= BASE;
      }

      while (carry) {
        digits.push(carry % BASE);
        carry = (carry / BASE) | 0;
      }
    }

    var zeros = maxEncodedLen(buffer.length * 8) - digits.length;
    // deal with leading zeros
    for (i = 0; i < zeros; i++) digits.push(0);

    return digits.reverse().map(function (digit) { return ALPHABET[digit]; }).join('');
  };

  Base58.decode = function (string) {
    if (string.length === 0) return [];

    var i, j, bytes = [0];
    for (i = 0; i < string.length; i++) {
      var c = string[i];
      if (!(c in ALPHABET_MAP)) throw new Error('Non-base58 character');

      for (j = 0; j < bytes.length; j++) bytes[j] *= BASE;
      bytes[0] += ALPHABET_MAP[c];

      var carry = 0;
      for (j = 0; j < bytes.length; ++j) {
        bytes[j] += carry;

        carry = bytes[j] >> 8;
        bytes[j] &= 0xff;
      }

      while (carry) {
        bytes.push(carry & 0xff);

        carry >>= 8;
      }
    }

    var zeros = decodedLen(string.length) - bytes.length;

    // deal with leading zeros
    for (i = 0; i < zeros; i++) bytes.push(0);

    return new Uint8Array(bytes.reverse());
  };
})();

module.exports = Base58;