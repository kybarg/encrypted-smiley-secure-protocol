const { Transform } = require('stream')

const SSP_STX = 0x7f

class SSPParser extends Transform {
  constructor(options = {}) {
    super(options)

    this.counter = 0
    this.checkStuff = 0
  }

  // this is converted from C++ SDK with edits:
  // discards falty data
  _transform(chunk, encoding, cb) {
    for (let ndx = 0; ndx < chunk.length; ndx++) {
      const byte = chunk[ndx]

      if (byte == SSP_STX && this.counter == 0) {
        // packet start
        this.buffer = Buffer.from([byte])
        this.counter++
      } else if (byte == SSP_STX && this.counter == 1) {
        // reset if started from stuffed byte
        this.reset()
      } else if (this.counter > 0) {
        // if last byte was start byte, and next is not then
        // restart the packet
        if (this.checkStuff == 1) {
          if (byte != SSP_STX) {
            this.buffer = Buffer.concat([this.buffer, Buffer.from([SSP_STX, byte])])
            this.counter = 2
          } else {
            this.buffer = Buffer.concat([this.buffer, Buffer.from([byte])])
            this.counter++
          }
          // reset stuff check flag
          this.checkStuff = 0
        } else {
          // set flag for stuffed byte check
          if (byte == SSP_STX) this.checkStuff = 1
          else {
            // add data to packet
            this.buffer = Buffer.concat([this.buffer, Buffer.from([byte])])
            this.counter++
          }
        }
        // are we at the end of the packet
        if (this.buffer[2] && this.counter === this.buffer[2] + 5) {
          // reset packet
          this.push(this.buffer)
          this.reset()
        }
      }
    }

    cb()
  }

  reset() {
    this.counter = 0
    this.checkStuff = 0
    this.buffer = Buffer.alloc(0)
  }

  _flush(cb) {
    this.push(this.buffer)
    this.reset()
    cb()
  }
}

module.exports = { SSPParser }
