const { argsToByte, absBigInt, encrypt, decrypt, randomInt, CRC16, readBytesFromBuffer, int64LE, int32LE, int16LE, uInt16LE } = require('./utils')

describe('absBigInt', () => {
  test('should return 1 for -1', () => {
    const num = BigInt(-1)
    expect(absBigInt(num)).toBe(BigInt(1))
  })

  test('should return 1 for 1', () => {
    const num = BigInt(1)
    expect(absBigInt(num)).toBe(BigInt(1))
  })
})

describe('encrypt', () => {
  const key = Buffer.concat([Buffer.from('0123456701234567', 'hex').swap64(), int64LE(23150n)])
  const data = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

  test('should encrypt data using AES encryption with ECB mode', () => {
    const encryptedData = encrypt(key, data)
    expect(encryptedData).toBeDefined()
    expect(encryptedData).toBeInstanceOf(Buffer)
    expect(encryptedData.length).toBeGreaterThan(0)
    expect(encryptedData).not.toEqual(data) // Encrypted data should not be the same as original data
  })

  test('should throw an error if key is not provided', () => {
    expect(() => {
      encrypt(null, data)
    }).toThrow('Key must be a Buffer')
  })

  test('should throw an error if key is not a Buffer', () => {
    expect(() => {
      encrypt('not a buffer', data)
    }).toThrow('Key must be a Buffer')
  })

  test('should throw an error if data is not provided', () => {
    expect(() => {
      encrypt(key, null)
    }).toThrow('Data must be a Buffer')
  })

  test('should throw an error if data is not a Buffer', () => {
    expect(() => {
      encrypt(key, 'not a buffer')
    }).toThrow('Data must be a Buffer')
  })
})

describe('decrypt', () => {
  const key = Buffer.concat([Buffer.from('0123456701234567', 'hex').swap64(), int64LE(23150n)])
  const data = Buffer.from([134, 163, 14, 111, 155, 193, 109, 210, 180, 37, 128, 45, 45, 157, 68, 152])

  // Encrypt the original data to get the encrypted data
  const encryptedData = encrypt(key, data)

  test('should decrypt data using AES decryption with ECB mode', () => {
    const decryptedData = decrypt(key, encryptedData)
    expect(decryptedData).toBeDefined()
    expect(decryptedData).toBeInstanceOf(Buffer)
    expect(decryptedData.length).toBeGreaterThan(0)
    expect(decryptedData).toEqual(data) // Decrypted data should be the same as original data
  })

  test('should throw an error if key is not provided', () => {
    expect(() => {
      decrypt(null, encryptedData)
    }).toThrow('Key must be a Buffer')
  })

  test('should throw an error if key is not a Buffer', () => {
    expect(() => {
      decrypt('not a buffer', encryptedData)
    }).toThrow('Key must be a Buffer')
  })

  test('should throw an error if data is not provided', () => {
    expect(() => {
      decrypt(key, null)
    }).toThrow('Data must be a Buffer')
  })

  test('should throw an error if data is not a Buffer', () => {
    expect(() => {
      decrypt(key, 'not a buffer')
    }).toThrow('Data must be a Buffer')
  })
})

describe('readBytesFromBuffer', () => {
  test('should return a new Buffer with the specified bytes', () => {
    const buffer = Buffer.from([1, 2, 3, 4, 5])
    const result = readBytesFromBuffer(buffer, 1, 3)
    expect(result).toEqual(Buffer.from([2, 3, 4]))
  })

  test('should throw an error if input is not a Buffer', () => {
    expect(() => {
      readBytesFromBuffer('not a buffer', 0, 3)
    }).toThrow('Input must be a Buffer object')
  })

  test('should throw an error if start index is negative', () => {
    const buffer = Buffer.from([1, 2, 3])
    expect(() => {
      readBytesFromBuffer(buffer, -1, 2)
    }).toThrow('Invalid start index')
  })

  test('should throw an error if start index is greater than buffer length', () => {
    const buffer = Buffer.from([1, 2, 3])
    expect(() => {
      readBytesFromBuffer(buffer, 4, 2)
    }).toThrow('Invalid start index')
  })

  test('should throw an error if length is negative', () => {
    const buffer = Buffer.from([1, 2, 3])
    expect(() => {
      readBytesFromBuffer(buffer, 0, -2)
    }).toThrow('Invalid length or exceeds buffer size')
  })

  test('should throw an error if length exceeds buffer size', () => {
    const buffer = Buffer.from([1, 2, 3])
    expect(() => {
      readBytesFromBuffer(buffer, 0, 4)
    }).toThrow('Invalid length or exceeds buffer size')
  })

  test('should handle reading from an empty buffer', () => {
    const buffer = Buffer.from([])
    expect(() => {
      readBytesFromBuffer(buffer, 0, 1)
    }).toThrow('Invalid start index')
  })

  test('should handle reading zero length from buffer', () => {
    const buffer = Buffer.from([1, 2, 3])
    const result = readBytesFromBuffer(buffer, 0, 0)
    expect(result).toEqual(Buffer.from([]))
  })
})

describe('randomInt', () => {
  test('should return random int', () => {
    const int = randomInt(10, 100)

    expect(typeof int).toBe('number')
    expect(int >= 10).toBeTruthy()
    expect(int <= 100).toBeTruthy()
  })
})

describe('CRC16', () => {
  test('should return CRC16', () => {
    const data = Buffer.from([0x01, 0x02, 0x03, 0x04])
    expect(CRC16(data)).toEqual([23, 158])
  })
})

describe('int64LE', () => {
  test('should return int64LE', () => {
    expect(int64LE(23150n)).toEqual(Buffer.from([0x6e, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
  })
})

describe('int32LE', () => {
  test('should return int32LE', () => {
    expect(int32LE(25)).toEqual(Buffer.from([0x19, 0x00, 0x00, 0x00]))
  })
})

describe('int16LE', () => {
  test('should return int16LE', () => {
    expect(int16LE(25)).toEqual(Buffer.from([0x19, 0x00]))
  })
})

describe('uInt16LE', () => {
  test('should return a Buffer representing the given unsigned 16-bit integer in little-endian format', () => {
    const number = 1234
    const result = uInt16LE(number)
    expect(result).toBeDefined()
    expect(result).toBeInstanceOf(Buffer)
    expect(result).toHaveLength(2)
    expect(result.readUInt16LE()).toBe(number)
  })

  test('should throw an error if input is not an unsigned 16-bit integer', () => {
    expect(() => {
      uInt16LE(-1)
    }).toThrow('Input must be an unsigned 16-bit integer')

    expect(() => {
      uInt16LE(65536)
    }).toThrow('Input must be an unsigned 16-bit integer')

    expect(() => {
      uInt16LE('not a number')
    }).toThrow('Input must be an unsigned 16-bit integer')
  })
})

describe('argsToByte function', () => {
  test('SET_GENERATOR', () => {
    const result = argsToByte('SET_GENERATOR', { key: 982451653 }, 6)
    expect(result).toEqual([0xc5, 0x05, 0x8f, 0x3a, 0x00, 0x00, 0x00, 0x00])
  })

  test('SET_MODULUS', () => {
    const result = argsToByte('SET_MODULUS', { key: 1287821 }, 6)
    expect(result).toEqual([0x8d, 0xa6, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00])
  })

  test('REQUEST_KEY_EXCHANGE', () => {
    const result = argsToByte('REQUEST_KEY_EXCHANGE', { key: 7554354432121 }, 6)
    expect(result).toEqual([0x79, 0xc8, 0x9c, 0xe2, 0xde, 0x06, 0x00, 0x00])
  })

  test('SET_DENOMINATION_ROUTE: protocol < 6', () => {
    const result = argsToByte('SET_DENOMINATION_ROUTE', { route: 'cashbox', value: 10 }, 5)
    expect(result).toEqual([0x01, 0x0a, 0x00, 0x00, 0x00])
  })

  test('SET_DENOMINATION_ROUTE: protocol >= 6', () => {
    const result = argsToByte('SET_DENOMINATION_ROUTE', { route: 'payout', value: 10, country_code: 'EUR' }, 6)
    expect(result).toEqual([0x00, 0x0a, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52])
  })

  test('SET_CHANNEL_INHIBITS', () => {
    const result = argsToByte('SET_CHANNEL_INHIBITS', { channels: [1, 2, 3] }, 6)
    expect(result).toEqual([0x07, 0x00])
  })

  test('SET_COIN_MECH_GLOBAL_INHIBIT', () => {
    const result = argsToByte('SET_COIN_MECH_GLOBAL_INHIBIT', { enable: true }, 6)
    expect(result).toEqual([0x01])
  })

  test('SET_HOPPER_OPTIONS', () => {
    const result = argsToByte('SET_HOPPER_OPTIONS', { payMode: 0, levelCheck: false, motorSpeed: 1, cashBoxPayAcive: false }, 6)
    expect(result).toEqual([0x04, 0x00])
  })

  test('GET_DENOMINATION_ROUTE: protocol < 6', () => {
    const result = argsToByte('GET_DENOMINATION_ROUTE', { value: 500 }, 5)
    expect(result).toEqual([0xf4, 0x01, 0x00, 0x00])
  })

  test('GET_DENOMINATION_ROUTE: hopper, protocol < 6', () => {
    const result = argsToByte('GET_DENOMINATION_ROUTE', { value: 500, isHopper: true }, 5)
    expect(result).toEqual([0xf4, 0x01])
  })

  test('GET_DENOMINATION_ROUTE: protocol >= 6', () => {
    const result = argsToByte('GET_DENOMINATION_ROUTE', { value: 500, country_code: 'EUR' }, 6)
    expect(result).toEqual([0xf4, 0x01, 0x00, 0x00, 0x45, 0x55, 0x52])
  })

  test('SET_DENOMINATION_LEVEL: protocol < 6', () => {
    const result = argsToByte('SET_DENOMINATION_LEVEL', { value: 20, denomination: 50 }, 5)
    expect(result).toEqual([0x14, 0x00, 0x32, 0x00])
  })

  test('SET_DENOMINATION_LEVEL: protocol >= 6', () => {
    const result = argsToByte('SET_DENOMINATION_LEVEL', { value: 12, denomination: 100, country_code: 'EUR' }, 6)
    expect(result).toEqual([0x0c, 0x00, 0x64, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52])
  })

  test('SET_REFILL_MODE: on', () => {
    const result = argsToByte('SET_REFILL_MODE', { mode: 'on' }, 6)
    expect(result).toEqual([0x05, 0x81, 0x10, 0x11, 0x01])
  })

  test('SET_REFILL_MODE: off', () => {
    const result = argsToByte('SET_REFILL_MODE', { mode: 'off' }, 6)
    expect(result).toEqual([0x05, 0x81, 0x10, 0x11, 0x00])
  })

  test('SET_REFILL_MODE: get', () => {
    const result = argsToByte('SET_REFILL_MODE', { mode: 'get' }, 6)
    expect(result).toEqual([0x05, 0x81, 0x10, 0x01])
  })

  test('HOST_PROTOCOL_VERSION', () => {
    const result = argsToByte('HOST_PROTOCOL_VERSION', { version: 6 }, 6)
    expect(result).toEqual([0x06])
  })

  test('SET_BAR_CODE_CONFIGURATION', () => {
    const result = argsToByte('SET_BAR_CODE_CONFIGURATION', { enable: 'both', numChar: 18 }, 6)
    expect(result).toEqual([0x03, 0x01, 0x12])
  })

  test('SET_BAR_CODE_CONFIGURATION: bound low', () => {
    const result = argsToByte('SET_BAR_CODE_CONFIGURATION', { enable: 'both', numChar: 5 }, 6)
    expect(result).toEqual([0x03, 0x01, 0x06])
  })

  test('SET_BAR_CODE_CONFIGURATION: bound up', () => {
    const result = argsToByte('SET_BAR_CODE_CONFIGURATION', { enable: 'both', numChar: 30 }, 6)
    expect(result).toEqual([0x03, 0x01, 0x18])
  })

  test('SET_BAR_CODE_INHIBIT_STATUS', () => {
    const result = argsToByte('SET_BAR_CODE_INHIBIT_STATUS', { currencyRead: true, barCode: true }, 6)
    expect(result).toEqual([0xff])
  })

  test('SET_BAR_CODE_INHIBIT_STATUS: turned off', () => {
    const result = argsToByte('SET_BAR_CODE_INHIBIT_STATUS', { currencyRead: false, barCode: false }, 6)
    expect(result).toEqual([0xfc])
  })

  test('PAYOUT_AMOUNT: protocol < 6', () => {
    const result = argsToByte('PAYOUT_AMOUNT', { amount: 500 }, 4)
    expect(result).toEqual([0xf4, 0x01, 0x00, 0x00])
  })

  test('PAYOUT_AMOUNT: protocol >= 6', () => {
    const result = argsToByte('PAYOUT_AMOUNT', { amount: 500, country_code: 'EUR' }, 6)
    expect(result).toEqual([0xf4, 0x01, 0x00, 0x00, 0x45, 0x55, 0x52, 0x58])
  })

  test('PAYOUT_AMOUNT: protocol >= 6, test', () => {
    const result = argsToByte('PAYOUT_AMOUNT', { test: true, amount: 500, country_code: 'EUR' }, 6)
    expect(result).toEqual([0xf4, 0x01, 0x00, 0x00, 0x45, 0x55, 0x52, 0x19])
  })

  test('GET_DENOMINATION_LEVEL: protocol < 6', () => {
    const result = argsToByte('GET_DENOMINATION_LEVEL', { amount: 10 }, 5)
    expect(result).toEqual([0x0a, 0x00, 0x00, 0x00])
  })

  test('GET_DENOMINATION_LEVEL: protocol >= 6', () => {
    const result = argsToByte('GET_DENOMINATION_LEVEL', { amount: 500, country_code: 'EUR' }, 6)
    expect(result).toEqual([0xf4, 0x01, 0x00, 0x00, 0x45, 0x55, 0x52])
  })

  test('FLOAT_AMOUNT: protocol < 6', () => {
    const result = argsToByte('FLOAT_AMOUNT', { min_possible_payout: 50, amount: 10000 }, 5)
    expect(result).toEqual([0x32, 0x00, 0x10, 0x27, 0x00, 0x00])
  })

  test('FLOAT_AMOUNT: protocol >= 6', () => {
    const result = argsToByte('FLOAT_AMOUNT', { min_possible_payout: 50, amount: 10000, country_code: 'EUR' }, 6)
    expect(result).toEqual([0x32, 0x00, 0x10, 0x27, 0x00, 0x00, 0x45, 0x55, 0x52, 0x58])
  })

  test('FLOAT_AMOUNT: protocol >= 6, test', () => {
    const result = argsToByte('FLOAT_AMOUNT', { test: true, min_possible_payout: 50, amount: 10000, country_code: 'EUR' }, 6)
    expect(result).toEqual([0x32, 0x00, 0x10, 0x27, 0x00, 0x00, 0x45, 0x55, 0x52, 0x19])
  })

  test('SET_COIN_MECH_INHIBITS: protocol < 6', () => {
    const result = argsToByte('SET_COIN_MECH_INHIBITS', { inhibited: true, amount: 100 }, 5)
    expect(result).toEqual([0x00, 0x64, 0x00])
  })

  test('SET_COIN_MECH_INHIBITS: protocol >= 6', () => {
    const result = argsToByte('SET_COIN_MECH_INHIBITS', { inhibited: false, amount: 50, country_code: 'EUR' }, 6)
    expect(result).toEqual([0x01, 0x32, 0x00, 0x45, 0x55, 0x52])
  })

  test('FLOAT_BY_DENOMINATION', () => {
    const value = [
      { number: 4, denomination: 100, country_code: 'EUR' },
      { number: 5, denomination: 10, country_code: 'EUR' },
      { number: 3, denomination: 100, country_code: 'GBP' },
      { number: 2, denomination: 50, country_code: 'GBP' },
    ]

    const result = argsToByte('FLOAT_BY_DENOMINATION', { value }, 6)
    expect(result).toEqual([
      0x04, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x03, 0x00, 0x64, 0x00, 0x00,
      0x00, 0x47, 0x42, 0x50, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x47, 0x42, 0x50, 0x58,
    ])
  })

  test('FLOAT_BY_DENOMINATION: test', () => {
    const value = [
      { number: 4, denomination: 100, country_code: 'EUR' },
      { number: 5, denomination: 10, country_code: 'EUR' },
      { number: 3, denomination: 100, country_code: 'GBP' },
      { number: 2, denomination: 50, country_code: 'GBP' },
    ]

    const result = argsToByte('FLOAT_BY_DENOMINATION', { value, test: true }, 6)
    expect(result).toEqual([
      0x04, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x03, 0x00, 0x64, 0x00, 0x00,
      0x00, 0x47, 0x42, 0x50, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x47, 0x42, 0x50, 0x19,
    ])
  })

  test('PAYOUT_BY_DENOMINATION', () => {
    const value = [
      { number: 4, denomination: 100, country_code: 'EUR' },
      { number: 5, denomination: 10, country_code: 'EUR' },
      { number: 3, denomination: 100, country_code: 'GBP' },
      { number: 2, denomination: 50, country_code: 'GBP' },
    ]

    const result = argsToByte('PAYOUT_BY_DENOMINATION', { value }, 6)
    expect(result).toEqual([
      0x04, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x03, 0x00, 0x64, 0x00, 0x00,
      0x00, 0x47, 0x42, 0x50, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x47, 0x42, 0x50, 0x58,
    ])
  })

  test('PAYOUT_BY_DENOMINATION: test', () => {
    const value = [
      { number: 4, denomination: 100, country_code: 'EUR' },
      { number: 5, denomination: 10, country_code: 'EUR' },
      { number: 3, denomination: 100, country_code: 'GBP' },
      { number: 2, denomination: 50, country_code: 'GBP' },
    ]

    const result = argsToByte('PAYOUT_BY_DENOMINATION', { value, test: true }, 6)
    expect(result).toEqual([
      0x04, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x45, 0x55, 0x52, 0x03, 0x00, 0x64, 0x00, 0x00,
      0x00, 0x47, 0x42, 0x50, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x47, 0x42, 0x50, 0x19,
    ])
  })

  test('SET_VALUE_REPORTING_TYPE', () => {
    const result = argsToByte('SET_VALUE_REPORTING_TYPE', { reportBy: 'channel' }, 6)
    expect(result).toEqual([0x01])
  })

  test('SET_BAUD_RATE: 9600', () => {
    const result = argsToByte('SET_BAUD_RATE', { baudrate: 9600, reset_to_default_on_reset: true }, 6)
    expect(result).toEqual([0x00, 0x00])
  })

  test('SET_BAUD_RATE: 38400', () => {
    const result = argsToByte('SET_BAUD_RATE', { baudrate: 38400, reset_to_default_on_reset: true }, 6)
    expect(result).toEqual([0x01, 0x00])
  })

  test('SET_BAUD_RATE: 115200', () => {
    const result = argsToByte('SET_BAUD_RATE', { baudrate: 115200, reset_to_default_on_reset: false }, 6)
    expect(result).toEqual([0x02, 0x01])
  })

  test('CONFIGURE_BEZEL', () => {
    const result = argsToByte('CONFIGURE_BEZEL', { RGB: 'FF0000', volatile: false }, 6)
    expect(result).toEqual([0xff, 0x00, 0x00, 0x01])
  })

  test('ENABLE_PAYOUT_DEVICE', () => {
    const result = argsToByte('ENABLE_PAYOUT_DEVICE', { GIVE_VALUE_ON_STORED: true, OPTIMISE_FOR_PAYIN_SPEED: true }, 6)
    expect(result).toEqual([0x03])
  })

  test('SET_FIXED_ENCRYPTION_KEY', () => {
    const result = argsToByte('SET_FIXED_ENCRYPTION_KEY', { fixedKey: '0123456701234567' }, 6)
    expect(result).toEqual(Buffer.from([0x67, 0x45, 0x23, 0x01, 0x67, 0x45, 0x23, 0x01]))
  })

  test('COIN_MECH_OPTIONS', () => {
    const result = argsToByte('COIN_MECH_OPTIONS', { ccTalk: true }, 6)
    expect(result).toEqual([0x01])
  })

  test('empty if no args', () => {
    const result = argsToByte('RANDOM_COMMAND_TEST', undefined, 6)
    expect(result).toEqual([])
  })

  test('empty if unknown command', () => {
    const result = argsToByte('RANDOM_COMMAND_TEST', { param: true }, 6)
    expect(result).toEqual([])
  })

  // Add more tests for other commands and scenarios
})
