const crypto = require('crypto')

class PwHasher {
  constructor (iterations = 10000) {
    this.iterations = iterations
  }
  
  hash (password, salt) {
    salt = salt ? salt : this.generateSalt()
    return password
      ? this.makeKey(password, salt)
      : this.error('No password provided')
  }

  verify (password, hashedPassword) {
    let parts, salt, hashed

    return !password
      ? this.error('No password provided')

      : !hashedPassword
      ? this.error('No hashed password provided')

      : (parts = hashedPassword.split('$')) && !this.checkParts(parts)
      ? this.error('Hash not formatted correctly')

      : !({salt, hashed} = this.getParts(parts)) || !salt || !hashed
      ? this.error('Wrong algorithm and/or iterations')

      : this.checkHash(password, salt, hashed)
  }

  generateSalt () {
    return crypto.randomBytes(64).toString('hex')
  }

  makeKey (password, salt) {
    const parts = [
      this.generateHash('pbkdf2', salt),
      this.generateHash(this.iterations.toString(), salt),
      this.generateHash(password, salt),
      salt
    ]

    return Array.from(Array(parts.length)).map((val, i) => {
      const start = this.getRandomNumber(parts.length - i)
      return parts.splice(start, 1)
    }).join('$')
  }

  getRandomNumber (max) {
    return Math.floor(Math.random() * max)
  }

  generateHash (password, salt) {
    salt = new Buffer(salt)

    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha1')
    return hash.toString('hex')
  }

  checkParts (parts) {
    return parts.length === 4 && parts
      .reduce((valid, part) => !valid ? false : !!part, true)
  }

  getParts (parts) {
    return parts.reduce((obj, salt) => {
      return Object.keys(obj).length
        ? obj
        : this.testPart(salt, parts)
    }, {})
  }

  testPart (salt, parts) {
    const tenk = this.generateHash('10000', salt)
    const pbkdf2 = this.generateHash('pbkdf2', salt)
    return parts.indexOf(tenk) > -1
      ? {
        salt,
        hashed: parts.filter(part => this.filterParts(part, tenk, pbkdf2, salt))[0]
      }
      : {}
  }

  filterParts (part, tenk, pbkdf2, salt) {
    return part !== tenk
      && part !== pbkdf2
      && part !== salt
  }

  checkHash (password, salt, hashed) {
    return hashed === this.generateHash(password, salt)
  }

  error (error) {
    throw new Error(error)
  }
}

const pwHasher = new PwHasher()
//  pwHasher.verify('secret', 'new$10000$5e45$5e45')
module.exports = {
  hash: pwHasher.hash.bind(pwHasher),
  verify: pwHasher.verify.bind(pwHasher)
}
