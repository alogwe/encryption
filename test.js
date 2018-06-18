const encryption = require('./index.js');
const file = require('./file-ops.js');
const test = require('tape');


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
test('encrypt/decrypt files (using default key file)', (t) => {
  const testData = createTestData();
  const tmpDir = './test/tmp/';
  const inFile = `${tmpDir}input.json`;
  const encryptedFile = `${tmpDir}encrypted`;
  const outFile = `${tmpDir}decrypted.json`;

  file.write(inFile, testData)
    .then(() => encryption.encrypt('Password!IsUsed@byPBKDF2function2Cre4teK3y', inFile, encryptedFile))
    .then(() => encryption.decrypt(encryptedFile, outFile))
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
      // Cleanup
      // TODO: Delete files
    });
});
