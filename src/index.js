const { generatePrimeSync, randomBytes } = require('node:crypto')
const { once, EventEmitter } = require('node:events')
const { satisfies } = require('semver')
const { SerialPort } = require('serialport')
const chalk = require('chalk')
const { parseData, CRC16, randHexArray, argsToByte, int64LE, encrypt, decrypt, absBigInt } = require('./utils.js')
const commandList = require('./command.js')
const { SSPParser } = require('./parser/index.js')
const { engines } = require('../package.json')

class SSP extends EventEmitter {
  constructor(param) {
    super()

    if (!satisfies(process.version, engines.node)) {
      throw new Error(`Version Node.js must be ${engines.node}`)
    }

    this.eventEmitter = new EventEmitter()

    this.debug = param.debug || false
    this.id = param.id || 0
    this.timeout = param.timeout || 3000
    this.encryptAllCommand = param.encryptAllCommand || true
    this.encryptKey = null
    this.keys = {
      fixedKey: param.fixedKey || '0123456701234567',
      generator: null,
      modulus: null,
      hostRandom: null,
      hostInter: null,
      slaveInterKey: null,
      key: null,
    }

    this.sequence = 0x80
    this.count = 0
    this.unit_type = null
    this.enabled = false
    this.polling = false
    this.commandTimeout = null

    this.processing = false

    // this.protocol_version = 8
    // this.unit_type = 'sdfas'
  }

  async open(port, param = {}) {
    this.port = new SerialPort({
      path: port,
      baudRate: param.baudRate || 9600,
      dataBits: param.dataBits || 8,
      stopBits: param.stopBits || 2,
      parity: param.parity || 'none',
      highWaterMark: param.highWaterMark || 64 * 1024,
      autoOpen: true,
    })

    await Promise.race([once(this.port, 'open'), once(this.port, 'close')])

    this.port.on('data', buffer => {
      this.emit('DATA_RECEIVED', { command: this.currentCommand, data: [...buffer], author: 'COM' })
    })

    this.port.on('error', error => {
      this.eventEmitter.emit('error', error)
    })

    this.parser = this.port.pipe(new SSPParser())
    this.parser.on('data', buffer => {
      this.eventEmitter.emit('DATA', buffer)
    })

    return
  }

  close() {
    if (this.port !== undefined) {
      this.port.close()
    }
  }

  getSequence() {
    return this.id | this.sequence
  }

  /**
   * Exchange encryption keys
   *
   * @returns {Promise} result
   */
  async initEncryption() {
    if (!this.initiateSSPHostKeys()) {
      throw new Error('Failed to generate keys')
    }

    const commands = [
      { command: 'SET_GENERATOR', args: { key: this.keys.generator } },
      { command: 'SET_MODULUS', args: { key: this.keys.modulus } },
      { command: 'REQUEST_KEY_EXCHANGE', args: { key: this.keys.hostInter } },
    ]

    let result
    for (const { command, args } of commands) {
      result = await this.command(command, args)
      if (!result || !result.success) {
        throw result
      }
    }

    this.count = 0

    return result
  }

  getPacket(command, args) {
    const STX = 0x7f
    const STEX = 0x7e

    if (commandList[command].args && args.length === 0) {
      throw new Error('Args missings')
    }

    let LENGTH = args.length + 1
    const SEQ_SLAVE_ID = this.getSequence()
    let DATA = [commandList[command].code].concat(...args)

    // Encrypted packet
    if (this.encryptKey !== null && (commandList[command].encrypted || this.encryptAllCommand)) {
      const eCOUNT = Buffer.alloc(4)
      eCOUNT.writeUInt32LE(this.count, 0)
      let eCommandLine = [DATA.length].concat([...eCOUNT], DATA)
      const ePACKING = randHexArray(Math.ceil((eCommandLine.length + 2) / 16) * 16 - (eCommandLine.length + 2))
      eCommandLine = eCommandLine.concat(ePACKING)
      eCommandLine = eCommandLine.concat(CRC16(eCommandLine))

      const eDATA = [...encrypt(this.encryptKey, Buffer.from(eCommandLine))]

      DATA = [STEX].concat(eDATA)
      LENGTH = DATA.length
    }

    const tmp = [SEQ_SLAVE_ID].concat(LENGTH, DATA)
    const comandLine = Buffer.from([STX].concat(tmp, CRC16(tmp)).join(',').replace(/,127/g, ',127,127').split(','))

    return comandLine
  }

  parsePacket(buffer, command) {
    buffer = [...buffer]
    if (buffer[0] === 0x7f) {
      buffer = buffer.slice(1)
      let DATA = buffer.slice(2, buffer[1] + 2)
      const CRC = CRC16(buffer.slice(0, buffer[1] + 2))

      if (CRC[0] !== buffer[buffer.length - 2] || CRC[1] !== buffer[buffer.length - 1]) {
        throw new Error('Wrong CRC16')
      }

      if (this.keys.key !== null && DATA[0] === 0x7e) {
        DATA = decrypt(this.encryptKey, Buffer.from(DATA.slice(1)))
        if (this.debug) {
          console.log('Decrypted:', chalk.red(Buffer.from(DATA).toString('hex')))
        }
        const eLENGTH = DATA[0]
        const eCOUNT = Buffer.from(DATA.slice(1, 5)).readInt32LE()
        DATA = DATA.slice(5, eLENGTH + 5)

        if (eCOUNT !== this.count + 1) {
          throw new Error('Encrypted counter mismatch')
        }

        this.count += 1
      }

      const parsedData = parseData(DATA, command, this.protocol_version, this.unit_type)

      if (this.debug) {
        console.log(parsedData)
      }

      if (parsedData.success) {
        if (command === 'REQUEST_KEY_EXCHANGE') {
          try {
            this.createSSPHostEncryptionKey(parsedData.info.key)
          } catch (error) {
            throw new Error('Key exchange error')
          }
        } else if (command === 'SETUP_REQUEST') {
          this.protocol_version = parsedData.info.protocol_version
          this.unit_type = parsedData.info.unit_type
        } else if (command === 'UNIT_DATA') {
          this.unit_type = parsedData.info.unit_type
        }
      } else {
        if (command === 'HOST_PROTOCOL_VERSION') {
          this.protocol_version = undefined
        }
      }

      return parsedData
    }

    throw new Error('Unknown response')
  }

  initiateSSPHostKeys() {
    this.keys.generator = generatePrimeSync(16, { bigint: true, safe: true })
    this.keys.modulus = generatePrimeSync(16, { bigint: true, safe: true })
    if (this.keys.generator < this.keys.modulus) {
      ;[this.keys.modulus, this.keys.generator] = [this.keys.generator, this.keys.modulus]
    }

    if (!this.createhostInterKey()) {
      return false
    }

    this.count = 0

    return true
  }

  createhostInterKey() {
    if (this.keys.generator === 0n || this.keys.modulus === 0n) {
      return false
    }

    this.keys.hostRandom = absBigInt(BigInt(randomBytes(64).readInt16LE())) % 32767n
    this.keys.hostInter = this.keys.generator ** this.keys.hostRandom % this.keys.modulus
    return true
  }

  createSSPHostEncryptionKey(data) {
    if (this.keys.key === null) {
      this.keys.slaveInterKey = Buffer.from(data).readBigInt64LE()
      this.keys.key = this.keys.slaveInterKey ** this.keys.hostRandom % this.keys.modulus
      this.encryptKey = Buffer.concat([Buffer.from(this.keys.fixedKey, 'hex').swap64(), int64LE(this.keys.key)])

      this.count = 0
      if (this.debug) {
        console.log('AES encrypt key:', chalk.red(`0x${Buffer.from(this.encryptKey).toString('hex')}`))
        console.log('')
        console.log(this.keys)
        console.log('')
      }
    }
  }

  async enable() {
    const result = await this.command('ENABLE')

    if (result.status === 'OK') {
      this.enabled = true
      if (!this.polling) await this.poll(true)
    }

    return result
  }

  async disable() {
    if (this.polling) await this.poll(false)

    const result = await this.command('DISABLE')

    if (result.status === 'OK') {
      this.enabled = false
    }

    return result
  }

  async command(command, args) {
    command = command.toUpperCase()
    if (commandList[command] === undefined) {
      throw new Error('Command not found')
    }

    if (this.processing) {
      throw new Error('Already processing another command')
    }

    if (command === 'SYNC') {
      this.sequence = 0x80
    }

    if (command === 'HOST_PROTOCOL_VERSION') {
      this.protocol_version = args.version
    }

    this.commandSendAttempts = 0

    const buffer = this.getPacket(command, argsToByte(command, args, this.protocol_version))
    this.emit('DATA_SENT', { command, data: [...buffer], author: 'HOST' })
    const result = await this.sendToDevice(command, buffer)

    // update sequence after response received
    this.sequence = this.sequence === 0x00 ? 0x80 : 0x00

    if (!result.success) {
      throw result
    }

    return result
  }

  async sendToDevice(command, txBuffer) {
    this.processing = true
    if (this.debug) {
      console.log('COM <-', chalk.cyan(txBuffer.toString('hex')), chalk.green(command), this.count, Date.now())
    }

    // Wait 1 second for reply.
    this.commandTimeout = setTimeout(() => {
      this.eventEmitter.emit('error', {
        success: false,
        status: 'TIMEOUT',
        command,
      })
    }, this.timeout)

    try {
      this.port.write(txBuffer)
      this.port.drain()
      this.commandSendAttempts += 1

      const [rxBuffer] = await once(this.eventEmitter, 'DATA')
      await new Promise(resolve => setTimeout(resolve, 100))

      this.processing = false
      clearTimeout(this.commandTimeout)

      if (this.debug) {
        console.log('COM ->', chalk.yellow(rxBuffer.toString('hex')), chalk.green(command), this.count, Date.now())
      }

      try {
        return this.parsePacket(rxBuffer, command)
      } catch (error) {
        return {
          success: false,
          error,
        }
      }
    } catch (error) {
      this.processing = false

      // Retry sending same command
      // After 20 retries, the master will assume that the slave has crashed.
      if (this.commandSendAttempts < 20) {
        return this.sendToDevice(command, txBuffer)
      } else {
        throw {
          success: false,
          error: 'Command failed afte 20 retries',
          reason: error,
        }
      }
    }
  }

  async poll(status = null) {
    if (status === true && this.polling === true) return Promise.resolve()

    if (status === true) {
      this.polling = true
    } else if (status === false) {
      this.polling = false

      return new Promise(resolve => {
        const interval = setInterval(() => {
          if (!this.processing) {
            clearInterval(interval)
            resolve()
          }
        }, 1)
      })
    }

    if (this.polling) {
      try {
        const startTime = Date.now()
        const result = await this.command('POLL')

        if (result.info) {
          let res = result.info
          if (!Array.isArray(result.info)) res = [result.info]

          res.forEach(info => {
            this.emit(info.name, info)
          })
        }
        const endTime = Date.now()
        const executionTime = endTime - startTime
        this.pollTimeout = setTimeout(() => this.poll(), executionTime >= 200 ? 0 : 200 - executionTime)

        return result
      } catch (error) {
        this.polling = false

        throw error
      }
    }
  }
}

module.exports = SSP
