const path = require('path');
const fs = require('fs');

let crypto;

try {
  crypto = require('crypto'); // eslint-disable-line global-require
} catch (err) {
  console.error('crypto support is disabled!', err);
  throw (err);
}

const algorithm = 'aes-256-cbc';
const encryptionEncoding = 'base64';
const debugMode = true;


/**
 * Saves data to a file
 * @param {String} file File path (including extension)
 * @param {String} data Data to write to the file
 * @returns {Promise} Promise resolves with the data that was written to the file
 */
function writeFile(file, data, encoding = 'utf8') {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(__dirname, file);
    fs.writeFile(fullPath, data, encoding, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
}


/**
 * TODO:
 * @param {String} file
 */
function readFile(file, encoding = 'utf8') {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(__dirname, file);
    fs.readFile(fullPath, encoding, (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
}


/**
 * @param {String} alg Algorithm
 */
function getByteSizeOfAlgorithm(alg) {
  let size = 0;
  if (alg === 'aes-256-cbc') {
    size = 16;
  }
  return size;
}


/**
 * Generates random bytes to be used as an initialization vector
 * @returns {String}
 */
function createInitVector() {
  const numBytes = getByteSizeOfAlgorithm(algorithm);
  const iv = crypto.randomBytes(numBytes).toString('base64');

  // ensure returned String cannot be longer than numBytes
  return iv.slice(0, numBytes);
}


/**
 * Log errors
 */
function logError(err) {
  console.error(err);
  if (debugMode) {
    throw err;
  }
}


/**
 * @returns {String} Derived hex key
 */
function createKey(password, keyLength) {
  return new Promise((resolve, reject) => {
    const salt = createInitVector(); // salt is also an init vector
    const iterations = 100e3;
    const digest = 'sha512';

    // derivedKey is <Buffer>;
    crypto.pbkdf2(password, salt, iterations, keyLength, digest, (err, derivedKey) => {
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
 * @returns
 */
function encrypt(password, inFile, outFile) {
  return new Promise((resolve, reject) => {
    const keyLength = getByteSizeOfAlgorithm(algorithm);
    let cipher;
    let iv;

    createKey(password, keyLength, outFile)
      .then((key) => {
        iv = createInitVector();
        writeFile(`${outFile}.key`, key);
        cipher = crypto.createCipheriv(algorithm, key, iv);
      })
      .then(() => readFile(inFile))
      .then((input) => {
        let data = cipher.update(input, 'utf8', encryptionEncoding);
        data += cipher.final(encryptionEncoding);
        const allData = iv + data;
        writeFile(outFile, allData);
        resolve(allData);
      })
      .catch((err) => {
        logError(err);
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
 * @returns {Promise} 
 */
function decrypt(keyFile, inFile, outFile) {
  return new Promise((resolve, reject) => {
    const ivSize = getByteSizeOfAlgorithm(algorithm);

    const readKey = readFile(keyFile);

    const readEncryptedFile = readFile(inFile).then(data => ({
      iv: data.substring(0, ivSize),
      data: data.substring(ivSize),
    }));

    Promise.all([readKey, readEncryptedFile])
      .then((values) => {
        const [key, encryptedFile] = values;
        const decipher = crypto.createDecipheriv(algorithm, key, encryptedFile.iv);
        const outputEncoding = 'utf8';

        let unencrypted = decipher.update(encryptedFile.data, encryptionEncoding, outputEncoding);
        unencrypted += decipher.final(outputEncoding);

        writeFile(outFile, unencrypted);
        resolve(unencrypted);
      })
      .catch((err) => {
        logError(err);
        reject(err);
      });
  });
}


encrypt('7&twHS!17PqRcc5N2$Aw', './ignored/input.json', './ignored/encrypted');

// decrypt('./ignored/encrypted.key', './ignored/encrypted', './ignored/decrypted.json');
