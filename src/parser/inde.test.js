const { assert } =  require('chai');
const sinon =  require('sinon');
const { SSPParser } =  require('./index');

describe('SSPParser', () => {
  it('transforms data to buffers split on a STX', () => {
    const spy = sinon.spy()
    const parser = new SSPParser()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 0, 1, 240, 32, 10]))
    parser.write(Buffer.from([127, 128, 1, 240, 35, 128]))
    parser.write(Buffer.from([/*start*/ 127, 0, 1]))
    parser.write(Buffer.from([240, 32, 10, /*start*/ 127, 128, 1]))
    parser.write(Buffer.from([240, 35, 128]))

    assert.deepEqual(spy.getCall(0).args[0], Buffer.from([127, 0, 1, 240, 32, 10]))
    assert.deepEqual(spy.getCall(1).args[0], Buffer.from([127, 128, 1, 240, 35, 128]))
    assert.deepEqual(spy.getCall(2).args[0], Buffer.from([127, 0, 1, 240, 32, 10]))
    assert.deepEqual(spy.getCall(3).args[0], Buffer.from([127, 128, 1, 240, 35, 128]))

    assert.equal(spy.callCount, 4)
  })

  it('deal with stuffed data', () => {
    const spy = sinon.spy()
    const parser = new SSPParser()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 0, 1, 127, 127, 32, 127, 127, /*start*/ 127]))
    parser.write(Buffer.from([128, 1, 240, 35, 128]))

    assert.deepEqual(spy.getCall(0).args[0], Buffer.from([127, 0, 1, 127, 32, 127]))
    assert.deepEqual(spy.getCall(1).args[0], Buffer.from([127, 128, 1, 240, 35, 128]))

    assert.equal(spy.callCount, 2)
  })

  it('discard falty data', () => {
    const spy = sinon.spy()
    const parser = new SSPParser()
    parser.on('data', spy)
    parser.write(Buffer.from([0, 1, 2, 3, /*start*/ 127]))
    parser.write(Buffer.from([128, 1, 240, 35, 128]))
    parser.write(Buffer.from([1, 2, 3, 4]))
    parser.write(Buffer.from([127, 128, 1, 240, 35, 128]))

    assert.deepEqual(spy.getCall(0).args[0], Buffer.from([127, 128, 1, 240, 35, 128]))
    assert.deepEqual(spy.getCall(1).args[0], Buffer.from([127, 128, 1, 240, 35, 128]))

    assert.equal(spy.callCount, 2)
  })

  it('discard falty stuffed data', () => {
    const spy = sinon.spy()
    const parser = new SSPParser()
    parser.on('data', spy)
    parser.write(Buffer.from([127, 127, 127, 127, /*start*/ 127]))
    parser.write(Buffer.from([128, 1, 240, 35, 128]))

    assert.deepEqual(spy.getCall(0).args[0], Buffer.from([127, 128, 1, 240, 35, 128]))

    assert.equal(spy.callCount, 1)
  })
})
