const encryption = require('../index.js');
const file = require('../lib/file-ops.js');
const util = require('util');
const path = require('path');
const tap = require('tap');
const rimraf = require('rimraf');

const rmrf = util.promisify(rimraf);

/**
 * @returns {String} Sample input data for test case
 */
function createTestData() {
  const obj = {
    username: 'TheDoctor',
    password: 'def34t%All#D4l3ks!',
    profile: {
      name: {
        first: 'Tennant',
        last: 'David',
      },
      age: 47,
      occupation: 'Time Lord',
    },
  };

  return JSON.stringify(obj, null, 2); // Formatting JSON
}


/**
 * Generates incremental folder names to isolate filesystem per test
 * and allow parallel execution.
 * @returns {String} folder name
 */
const generateTempDir = (() => {
  let testNum = 0;

  /**
   * Closure that generates next folder name
   */
  function nextFolderName() {
    testNum += 1;
    return path.join(__dirname, `.tmp/${testNum}`);
  }

  return nextFolderName;
})();


// write input file -> encrypt -> decrypt to output file -> compare input file to output file
tap.test('encrypt/decrypt files', async (t) => {
  const tmpDir = generateTempDir();
  const inFile = `${tmpDir}/input.json`;
  const keyFile = `${inFile}.key`;
  const encryptedFile = `${tmpDir}/encrypted`;
  const outFile = `${tmpDir}/decrypted.json`;

  await file.write(inFile, createTestData());
  await encryption.encrypt('Password!IsUsed@byPBKDF2function2Cre4teK3y', inFile, encryptedFile, keyFile);
  await encryption.decrypt(keyFile, encryptedFile, outFile);

  const readInputFile = file.read(inFile);
  const readOutputFile = file.read(outFile);

  const [input, output] = await Promise.all([readInputFile, readOutputFile]);

  t.equal(output, input, 'Decrypted output is equal to the input file data.');

  await rmrf(tmpDir);
  t.end();
});
