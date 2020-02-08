const encryption = require('./index.js');
const file = require('./file-ops.js');
const test = require('tape');
const rimraf = require('rimraf');


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


// write input file -> encrypt -> decrypt to output file -> compare input file to output file
test('encrypt/decrypt files', (t) => {
  const testData = createTestData();
  const tmpDir = './.tmp/';
  const inFile = `${tmpDir}input.json`;
  const keyFile = `${inFile}.key`;
  const encryptedFile = `${tmpDir}encrypted`;
  const outFile = `${tmpDir}decrypted.json`;

  file.write(inFile, testData)
    .then(() => encryption.encrypt('Password!IsUsed@byPBKDF2function2Cre4teK3y', inFile, encryptedFile, keyFile))
    .then(() => encryption.decrypt(keyFile, encryptedFile, outFile))
    .then(() => {
      const readInputFile = file.read(inFile);
      const readOutputFile = file.read(outFile);
      return Promise.all([readInputFile, readOutputFile]);
    })
    .then((values) => {
      const [input, output] = values;
      t.equal(output, input, 'Decrypted output is equal to the input file data.');
    })
    .then(() => {
      // TODO: Move cleanup function to afterEach() callback?
      rimraf(tmpDir, (err) => {
        if (err) {
          throw err;
        }
        t.end(); // end test to avoid false failure
      });
    });
});
