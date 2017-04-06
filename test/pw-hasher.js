'use strict'

var expect = require('chai').expect
var pwHasher = require('../index')

var splitHash = function(hash) {
  var opt = hash.split('$')
  if(opt.length !== 4)
    throw new Error('Hash expected to have four parts')
  return {
    algorithm: opt[0],
    iterations: opt[1],
    hash: opt[2],
    salt: opt[3]
  }
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

      const split = splitHash(hash)
      expect(split.algorithm).to.equal('pbkdf2')
      expect(split.iterations).to.equal('10000')
      expect(split.hash.length).to.be.at.least(10)
      expect(split.salt.length).to.be.at.least(10)
    })

    it('should create unique hashes', function () {
      const hash1 = pwHasher.hash('secret1')
      const hash2 = pwHasher.hash('secret2')

      expect(hash1).not.to.be.null
      expect(hash2).not.to.be.null
      expect(hash1).to.not.equal(hash2)
      
      expect(splitHash(hash1).hash).to.not.equal(splitHash(hash2).hash)
    })

    it('should create unique salts', () => {
      const hash1 = pwHasher.hash('secret1')
      const hash2 = pwHasher.hash('secret2')

      expect(hash1).not.to.be.null
      expect(hash2).not.to.be.null
      expect(hash1).to.not.equal(hash2)
      
      expect(splitHash(hash1).salt).to.not.equal(splitHash(hash2).salt)
    })

    it('should create same hash for same password and salt', () => {
      const hash1 = pwHasher.hash('secret')
      const salt1 = splitHash(hash1).salt

      const hash2 = pwHasher.hash('secret', salt1)
      const salt2 = splitHash(hash2).salt

      expect(hash1).to.equal(hash2)
      expect(salt1).to.equal(salt2)
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
      }).to.throw('Wrong algorithm and/or iterations')

      expect(() => {
        pwHasher.verify('secret', 'new$10000$5e45$5e45')
      }).to.throw('Wrong algorithm and/or iterations')
    })
    
    it('should not verify with wrong or empty iterations', () => {
      expect(() => {
        pwHasher.verify('secret', 'pbkdf2$$5e45$5e45')
      }).to.throw('Wrong algorithm and/or iterations')

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
      const verified = pwHasher.verify('secret', 'pbkdf2$10000$5e45$5e45')
      expect(verified).to.equal(false)
    })

    it('should verify correct passwords', () => {
      const hash = pwHasher.hash('secret')
      const verified = pwHasher.verify('secret', hash)
      expect(verified).to.equal(true)
    })
  })
})
