const path = require('path');
const fs = require('fs');
const makeDir = require('make-dir');


/**
 * Writes data to a file, attempting to create any directory named in the file that might not exist
 * @param {String} file File path (including extension)
 * @param {String} data Data to write
 * @param {String} encoding Specify file encoding type. Default: 'utf8'
 * @returns {Promise} Promise resolves with the data from the file
 */
function write(file, data, encoding = 'utf8') {
  return new Promise((resolve, reject) => {
    const fullPath = path.join(__dirname, file);
    makeDir(path.dirname(fullPath))
      .then(() => {
        fs.writeFile(fullPath, data, encoding, (fileErr) => {
          if (fileErr) {
            reject(fileErr);
          } else {
            resolve(data);
          }
        });
      });
  });
}


/**
 * Reads data from a file
 * @param {String} file File path (including extension)
 * @param {String} encoding Specify file encoding type. Default: 'utf8'
 * @returns {Promise} Promise resolves with the data from the file
 */
function read(file, encoding = 'utf8') {
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


module.exports = {
  write,
  read,
};
