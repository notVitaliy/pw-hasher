const expect = require('chai').expect
const pwHasher = require('../index')
const parts = [
  // hash => algo + salt
  '50db62b3b5a2af6efc4bbf4554513e51326f28d9644eeabbd378108a3626edd78945883de6e7ea8bc24e567000efc9ddbc31a589cdd7c8ace469ffa833ed3b4e',
  // hash => iterations + salt
  '1a8249ec061df024259de5c25823023aca27719931c484c73bcd60116359bdc789218695f17fee4c6b4e399c8e9dccebc4efd20ff2c1d979d6685597f09d63bc',
  // hash => pass + salt
  '494fe327b4d0099dcdeeaa37fbe4913bf6f7d8c0c4158be8e8f30b05a75ca920b170d08cb9747065ff9595c8fb4478eebb7c7b69421f736c1d28c37627f58eeb',
  // salt
  'cd6ce3518a966254906819febdf239a77f53a013e559cd33273fd602bdb4b303cb0d2b8777c42d03fc6af5cb92ac9a4fae232be1952292de4bec2fb9641cf262'
]

function shuffle (array) {
  var currentIndex = array.length, temporaryValue, randomIndex
  while (0 !== currentIndex) {
    randomIndex = Math.floor(Math.random() * currentIndex)
    currentIndex -= 1
    temporaryValue = array[currentIndex]
    array[currentIndex] = array[randomIndex]
    array[randomIndex] = temporaryValue
  }

  return array
}

describe('Password hash and salt', () => {
  describe('Hash creation', () => {
    it('should not hash empty passwords', () => {
      expect(() => {
        pwHasher.hash('')
      }).to.throw('No password provided')
      
    })

    it('should return a key formatted as: alg$iterations$hash$salt', () => {
      const hash = pwHasher.hash('secret')
      expect(hash).to.not.be.undefined
      expect(hash).to.not.be.null

      const split = hash.split('$')
      expect(split.length).to.equal(4)
      expect(split[0]).to.not.be.null
      expect(split[1]).to.not.be.null
      expect(split[2]).to.not.be.null
      expect(split[3]).to.not.be.null
    })

    it('should create unique hashes - 1', function () {
      const hash1 = pwHasher.hash('secret1')
      const hash2 = pwHasher.hash('secret2')

      expect(hash1).not.to.be.null
      expect(hash2).not.to.be.null
      expect(hash1).to.not.equal(hash2)
    })

    it('should create unique hashes - 2', function () {
      const hash1 = pwHasher.hash('secret')
      const hash2 = pwHasher.hash('secret')

      expect(hash1).not.to.be.null
      expect(hash2).not.to.be.null

      expect(hash1).to.not.equal(hash2)
    })
  })

  describe('Hash verification', () => {
    it('should not verify empty passwords', () => {
      expect(() => {
        pwHasher.verify('')
      }).to.throw('No password provided')
    })

    it('should not verify empty hashedPassword', () => {
      expect(() => {
        pwHasher.verify('secret', '')
      }).to.throw('No hashed password provided')
    })
    
    it('should not verify with empty salt', () => {
      expect(() => {
        pwHasher.verify('secret', 'pbkdf2$10000$5e45$')
      }).to.throw('Hash not formatted correctly')
    })
    
    it('should not verify with empty hash', () => {
      expect(() => {
        pwHasher.verify('secret', 'pbkdf2$10000$$5e45')
      }).to.throw('Hash not formatted correctly')
    })
    
    it('should not verify with wrong or empty algorithm', () => {
      expect(() => {
        pwHasher.verify('secret', '$10000$5e45$5e45')
      }).to.throw('Hash not formatted correctly')

      expect(() => {
        pwHasher.verify('secret', 'new$10000$5e45$5e45')
      }).to.throw('Wrong algorithm and/or iterations')
    })
    
    it('should not verify with wrong or empty iterations', () => {
      expect(() => {
        pwHasher.verify('secret', 'pbkdf2$$5e45$5e45')
      }).to.throw('Hash not formatted correctly')

      expect(() => {
        pwHasher.verify('secret', 'pbkdf2$9999$5e45$5e45')
      }).to.throw('Wrong algorithm and/or iterations')
    })
    
    it('should not verify with wrongly formatted hash - 1', () => {
      expect(() => {
        pwHasher.verify('secret', 'random characters')
      }).to.throw('Hash not formatted correctly')
    })
    
    it('should not verify with wrongly formatted hash - 2', () => {
      expect(() => {
        pwHasher.verify('secret', 'alg$1000$5e45$5e45$something')
      }).to.throw('Hash not formatted correctly')
    })

    it('should not verify wrong passwords', () => {
      const hash = pwHasher.hash('secret')
      const verified = pwHasher.verify('not a secret', hash)
      expect(verified).to.equal(false)
    })

    it('should verify correct passwords - 1', () => {
      const hash = pwHasher.hash('secret')
      const verified = pwHasher.verify('secret', hash)
      expect(verified).to.equal(true)
    })

    it('should verify correct passwords - 2', () => {
      const hash = parts.join('$')
      const verified = pwHasher.verify('secret', hash)
      expect(verified).to.equal(true)
    })

    it('should verify correct passwords - 3', () => {
      const hash = parts.slice().reverse().join('$')
      const verified = pwHasher.verify('secret', hash)
      expect(verified).to.equal(true)
    })

    it('should verify correct passwords - 4', () => {
      const hash = shuffle(parts).join('$')
      const verified = pwHasher.verify('secret', hash)
      expect(verified).to.equal(true)
    })

    it('should verify correct passwords - 5', () => {
      const hash = pwHasher.hash('secret', parts[3])
      const verified = pwHasher.verify('secret', hash)
      expect(verified).to.equal(true)
    })
  })
})
