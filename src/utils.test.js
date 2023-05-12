const { absBigInt, encrypt, decrypt, randomInt, CRC16, randHexArray, int64LE, int32LE, int16LE } = require('./utils')

describe('absBigInt', () => {
  test('should return 1', () => {
    const num = BigInt(-1)
    expect(absBigInt(num)).toBe(BigInt(1))
  })
})

describe('encrpyt', () => {
  test('should encrypt data', () => {
    const data = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    const encryptKey = Buffer.concat([Buffer.from('0123456701234567', 'hex').swap64(), int64LE(23150n)])
    expect(encrypt(encryptKey, data)).toEqual(Buffer.from([134, 163, 14, 111, 155, 193, 109, 210, 180, 37, 128, 45, 45, 157, 68, 152]))
  })
})

describe('decrypt', () => {
  test('should encrypt data', () => {
    const data = Buffer.from([134, 163, 14, 111, 155, 193, 109, 210, 180, 37, 128, 45, 45, 157, 68, 152])
    const encryptKey = Buffer.concat([Buffer.from('0123456701234567', 'hex').swap64(), int64LE(23150n)])
    expect(decrypt(encryptKey, data)).toEqual(
      Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    )
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

describe('randHexArray', () => {
  test('should generate array of random data', () => {
    expect(randHexArray(4)).toHaveLength(4)
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
