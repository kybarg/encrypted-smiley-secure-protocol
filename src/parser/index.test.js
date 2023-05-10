const { assert } = require('chai')
const { test } = require('mocha')
const sinon = require('sinon')
const { SSPParser } = require('./index')

describe('SSPParser', () => {
  test('should parse a packet', () => {
    const parser = new SSPParser()
    const spy = sinon.spy()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 0, 1, 240, 32, 10]))
    assert.isTrue(spy.calledOnce)
    assert.isTrue(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 10])))
  })

  test('should parse a packet with a stuffed byte', () => {
    const parser = new SSPParser()
    const spy = sinon.spy()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 0, 1, 127, 127, 32, 10]))
    assert.isTrue(spy.calledOnce)
    assert.isTrue(spy.calledWith(Buffer.from([127, 0, 1, 127, 32, 10])))
  })

  test('should parse a packet with a stuffed byte at the end', () => {
    const parser = new SSPParser()
    const spy = sinon.spy()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 0, 1, 240, 32, 127, 127]))
    assert.isTrue(spy.calledOnce)
    assert.isTrue(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 127])))
  })

  test('should parse a packet with a stuffed byte at the end and a new packet', () => {
    const parser = new SSPParser()
    const spy = sinon.spy()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 0, 1, 240, 32, 127, 127, 127, 0, 1, 240, 32, 10]))
    assert.isTrue(spy.calledTwice)
    assert.isTrue(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 127])))
    assert.isTrue(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 10])))
  })

  test('should parse a packet with a stuffed byte at the end and a new packet with a stuffed byte', () => {
    const parser = new SSPParser()
    const spy = sinon.spy()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 0, 1, 240, 32, 127, 127, 127, 0, 2, 127, 127, 240, 32, 10]))
    assert.isTrue(spy.calledTwice)
    assert.isTrue(spy.calledWith(Buffer.from([127, 0, 1, 240, 32, 127])))
    assert.isTrue(spy.calledWith(Buffer.from([127, 0, 2, 127, 240, 32, 10])))
  })
})
