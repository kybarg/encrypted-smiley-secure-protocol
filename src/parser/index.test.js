const sinon = require('sinon')
const { SSPParser } = require('./index')

describe('SSPParser', () => {
  let parser
  let spy

  beforeEach(() => {
    parser = new SSPParser()
    spy = sinon.spy()
    parser.on('data', spy)
  })

  test('should parse a packet', () => {
    parser.write(Buffer.from([127, 0, 1, 240, 32, 10]))
    expect(spy.calledOnce).toBeTruthy()
    expect(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 10]))).toBeTruthy()
  })

  test('should parse a packet with a stuffed byte', () => {
    parser.write(Buffer.from([127, 0, 1, 127, 127, 32, 10]))
    expect(spy.calledOnce).toBeTruthy()
    expect(spy.calledWith(Buffer.from([127, 0, 1, 127, 32, 10]))).toBeTruthy()
  })

  test('should parse a packet with a stuffed byte at the end', () => {
    parser.write(Buffer.from([127, 0, 1, 240, 32, 127, 127]))
    expect(spy.calledOnce).toBeTruthy()
    expect(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 127]))).toBeTruthy()
  })

  test('should parse a packet with a stuffed byte at the end and a new packet', () => {
    parser.write(Buffer.from([127, 0, 1, 240, 32, 127, 127, 127, 0, 1, 240, 32, 10]))
    expect(spy.calledTwice).toBeTruthy()
    expect(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 127]))).toBeTruthy()
    expect(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 10]))).toBeTruthy()
  })

  test('should parse a packet with a stuffed byte at the end and a new packet with a stuffed byte', () => {
    parser.write(Buffer.from([127, 0, 1, 240, 32, 127, 127, 127, 0, 2, 127, 127, 240, 32, 10]))
    expect(spy.calledTwice).toBeTruthy()
    expect(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 127]))).toBeTruthy()
    expect(spy.calledWith(Buffer.from([127, 0, 2, 127, 240, 32, 10]))).toBeTruthy()
  })
})
