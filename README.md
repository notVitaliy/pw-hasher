pw-hasher
======================

This module provides straight-forward password hashing for node.js applications using default settings considered to be safe.

### Usage

First, install the module:

`$ npm install pw-hasher --save`

Afterwards, usage is as simple as shown in the following example:
```javascript
const pwHasher = require('../index')

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


```

### Crypto
password-hash-and-salt uses node.js' internal crypto module. Hashes are generated with pbkdf2 using 10,000 iterations.

### Created hash
The created hash is of 270 characters length and is of the following format:
`pbkdf2$10000$hash$salt`

This allows for future upgrades of the algorithm and/or increased number of iterations in future version. It also simplifies storage as no dedicated database field for the salt is required.

### Credits and License
Originally based of off https://github.com/florianheinemann/password-hash-and-salt

Copyright (c) 2017 Vitaliy Isikov
