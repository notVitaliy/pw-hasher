const pwHasher = require('../pw-hasher')

const myuser = []

try {
  myuser.hash = pwHasher.hash('mysecret')
} catch (e) {
  console.error(e)
}

let isValid = false;
try {
  isValid = pwHasher.verify('hack', myuser.hash)
} catch (e) {
  console.error(e)
}

if (!isValid) {
  console.log('Nope!')
} else {
  // Velcom to hte thing.
}
