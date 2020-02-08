const file = require('./file-ops.js');

let crypto;

try {
  crypto = require('crypto'); // eslint-disable-line global-require
} catch (err) {
  console.error('crypto support is disabled!', err);
  throw (err);
}

const CIPHERS = {
  AES_256_CBC: {
    name: 'aes-256-cbc',
    ivLength: 16, // bytes
    keyLength: 16, // bytes
    // fileEncoding: 'base64',
  },
};

// TODO: pass in through process.argv list, something like
// const algorithm = CIPHERS[process.argv[2]]
const algorithm = CIPHERS.AES_256_CBC;
const encryptionEncoding = 'base64';


/**
 * Generates random bytes to be used as an initialization vector
 * @returns {String}
 */
function createInitVector(numBytes) {
  const iv = crypto.randomBytes(numBytes).toString(encryptionEncoding);

  // TODO: remove this slice() ?
  // ensure returned String cannot be longer than numBytes
  return iv.slice(0, numBytes);
}


/**
 * Simple logging function
 */
function log(msg, fn = 'log', throws = false) {
  console[fn](msg);
  if (throws) {
    throw new Error(msg);
  }
}


/**
 * @returns {String} Derived hex key
 */
function createKey(password) {
  return new Promise((resolve, reject) => {
    const salt = createInitVector(algorithm.ivLength); // salt is also an init vector
    const iterations = 500e3;
    const digest = 'sha512';

    // derivedKey is <Buffer>;
    crypto.pbkdf2(password, salt, iterations, algorithm.keyLength, digest, (err, derivedKey) => {
      if (err) {
        reject(err);
      } else {
        resolve(derivedKey.toString('hex'));
      }
    });
  });
}


/**
 * Encrypt some data by generating a key (using password input)
 * Saves encrypted data and key file to disk.
 * @param {String} password Password used to generate key (pbkdf2)
 * @param {String} inFile File to be encrypted
 * @param {String} outFile Output file
 * @param {String} keyFile Key file to generate during encryption
 * @returns {Promise} Resolves with encrypted data (including pre-pended initialization vector);
 * Rejects on error;
 */
function encrypt(password, inFile, outFile, keyFile) {
  return new Promise((resolve, reject) => {
    let cipher;
    let iv;
    let allData;

    createKey(password)
      .then((key) => {
        iv = createInitVector(algorithm.ivLength);
        cipher = crypto.createCipheriv(algorithm.name, key, iv);
        return file.write(keyFile, key);
      })
      .then(() => file.read(inFile))
      .then((input) => {
        let data = cipher.update(input, 'utf8', encryptionEncoding);
        data += cipher.final(encryptionEncoding);
        allData = iv + data;
        return file.write(outFile, allData);
      })
      .then(() => resolve(allData))
      .catch((err) => {
        log(err);
        reject(err);
      });
  });
}


/**
 * Decrypts a file using the specified key file
 * Writes the unencrypted output to disk.
 * @param {String} keyFile Key file that was generated during encryption
 * @param {String} inFile Data to be decrypted
 * @param {String} outFile Filename for decrypted data
 * @returns {Promise} Resolves with decrypted data; Rejects on error;
 */
function decrypt(keyFile, inFile, outFile) {
  return new Promise((resolve, reject) => {
    // const ivSize = algorithm.byteSize;
    const { ivLength } = algorithm;
    const readKey = file.read(keyFile);

    const readEncryptedFile = file.read(inFile).then(data => ({
      iv: data.substring(0, ivLength),
      data: data.substring(ivLength),
    }));

    Promise.all([readKey, readEncryptedFile])
      .then((values) => {
        const [key, encryptedFile] = values;
        const decipher = crypto.createDecipheriv(algorithm.name, key, encryptedFile.iv);
        const outputEncoding = 'utf8';

        let unencrypted = decipher.update(encryptedFile.data, encryptionEncoding, outputEncoding);
        unencrypted += decipher.final(outputEncoding);

        return file.write(outFile, unencrypted);
      })
      .then((unencrypted) => {
        resolve(unencrypted);
      })
      .catch((err) => {
        log(err);
        reject(err);
      });
  });
}

module.exports = {
  CIPHERS,
  encrypt,
  decrypt,
};
