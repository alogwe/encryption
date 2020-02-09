const path = require('path');
const fsPromises = require('fs').promises; // https://nodejs.org/dist/v12.15.0/docs/api/fs.html#fs_fs_promises_api
const mkdir = require('make-dir');


/**
 * Writes data to a file, attempting to create any directory named in the file that might not exist
 * @param {String} fullPath File path (including extension)
 * @param {String} data Data to write
 * @param {String} encoding Specify file encoding type. Default: 'utf8'
 * @returns {Promise} Promise resolves with the data from the file
 */
async function write(fullPath, data, encoding = 'utf8') {
  await mkdir(path.dirname(fullPath));
  await fsPromises.writeFile(fullPath, data, encoding); // resolves undefined; no need to return?;
}


/**
 * Reads data from a file
 * @param {String} fullPath File path (including extension)
 * @param {String} encoding Specify file encoding type. Default: 'utf8'
 * @returns {Promise} Promise resolves with the data from the file
 */
async function read(fullPath, encoding = 'utf8') {
  const content = await fsPromises.readFile(fullPath, encoding);
  return content;
}


module.exports = {
  write,
  read,
};
