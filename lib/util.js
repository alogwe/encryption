/**
 * Simple logging function
 */
function log(msg, fn = 'log', throws = false) {
  console[fn](msg);
  if (throws) {
    throw new Error(msg);
  }
}


module.exports = {
  log,
};
