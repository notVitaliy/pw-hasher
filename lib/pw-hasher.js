const crypto = require('crypto')

class PwHasher {
  constructor (iterations = 10000) {
    this.iterations = iterations
  }
  
  hash (password, salt) {
    salt = salt ? salt : this.generateSalt()
    return password
      ? this.makeKey(password, salt.toString('hex'))
      : this.error('No password provided')
  }

  verify (password, hashedPassword) {
    let parts;

    return !password
      ? this.error('No password provided')

      : !hashedPassword
      ? this.error('No hashed password provided')

      : (parts = hashedPassword.split('$')) && !this.checkParts(parts)
      ? this.error('Hash not formatted correctly')

      : !this.checkAlgo(parts)
      ? this.error('Wrong algorithm and/or iterations')

      : this.checkHash(password, parts[3], hashedPassword)
  }

  generateSalt () {
    return crypto.randomBytes(64)
  }

  makeKey (password, salt) {
    return `pbkdf2$${this.iterations}$${this.generateHash(password, salt)}$${salt}`
  }

  generateHash (password, salt) {
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha1')
    return hash.toString('hex')
  }

  checkParts (parts) {
    return parts.length === 4 && parts[2] && parts[3]
  }

  checkAlgo (parts) {
    return parts[0] === 'pbkdf2' && parts[1] === this.iterations.toString()
  }

  checkHash (password, salt, hashedPassword) {
    return this.hash(password, salt) === hashedPassword
  }

  error (error) {
    throw new Error(error)
  }
}

const pwHasher = new PwHasher()

module.exports = {
  hash: pwHasher.hash.bind(pwHasher),
  verify: pwHasher.verify.bind(pwHasher)
}
