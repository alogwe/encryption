const file = require('./lib/file-ops.js');
const { log } = require('./lib/extras');
const util = require('util');

let crypto;

try {
  crypto = require('crypto'); // eslint-disable-line global-require
} catch (err) {
  console.error('crypto support is disabled!', err);
  throw (err);
}

// Create functions that use promises instead of callbacks
// for use with async/await
const cryptoPromises = {
  pbkdf2: util.promisify(crypto.pbkdf2),
};

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
 * @returns {String} Derived hex key
 */
async function createKey(password) {
  const salt = createInitVector(algorithm.ivLength); // salt is also an init vector
  const iterations = 500e3;
  const digest = 'sha512';
  const derivedKey = await cryptoPromises.pbkdf2(password, salt, iterations, algorithm.keyLength, digest);
  return derivedKey.toString('hex'); // derivedKey is <Buffer>;
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
async function encrypt(password, inFile, outFile, keyFile) {
  try {
    const key = await createKey(password);
    const iv = createInitVector(algorithm.ivLength);
    const cipher = crypto.createCipheriv(algorithm.name, key, iv);

    await file.write(keyFile, key);
    const input = await file.read(inFile);

    let data = cipher.update(input, 'utf8', encryptionEncoding);
    data += cipher.final(encryptionEncoding);

    // need to decrypt with same initialization vector and data
    await file.write(outFile, iv + data);
  } catch (e) {
    log(e);
  }
}


/**
 * Decrypts a file using the specified key file
 * Writes the unencrypted output to disk.
 * @param {String} keyFile Key file that was generated during encryption
 * @param {String} inFile Data to be decrypted
 * @param {String} outFile Filename for decrypted data
 * @returns {Promise} Resolves with decrypted data; Rejects on error;
 */
async function decrypt(keyFile, inFile, outFile) {
  const outputEncoding = 'utf8';
  try {
    const { ivLength } = algorithm;

    const readKey = file.read(keyFile);
    const readEncryptedFile = file.read(inFile).then(data => ({
      iv: data.substring(0, ivLength),
      data: data.substring(ivLength),
    }));
    const [key, encryptedFile] = await Promise.all([readKey, readEncryptedFile]);

    const decipher = crypto.createDecipheriv(algorithm.name, key, encryptedFile.iv);
    let unencryptedData = decipher.update(encryptedFile.data, encryptionEncoding, outputEncoding);
    unencryptedData += decipher.final(outputEncoding);
    await file.write(outFile, unencryptedData);
  } catch (err) {
    log(err);
  }
}

module.exports = {
  CIPHERS,
  encrypt,
  decrypt,
};
