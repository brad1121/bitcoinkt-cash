/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core

import org.bitcoinj.core.listeners.FeeFilterMessage
import org.bitcoinj.core.listeners.SendHeadersMessage
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.IOException
import java.io.OutputStream
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.util.HashMap

import org.bitcoinj.core.Utils.*

/**
 *
 * Methods to serialize and de-serialize messages to the Bitcoin network format as defined in
 * [the protocol specification](https://en.bitcoin.it/wiki/Protocol_specification).
 *
 *
 * To be able to serialize and deserialize new Message subclasses the following criteria needs to be met.
 *
 *
 *  * The proper Class instance needs to be mapped to its message name in the names variable below
 *  * There needs to be a constructor matching: NetworkParameters params, byte[] payload
 *  * Message.bitcoinSerializeToStream() needs to be properly subclassed
 *
 */
class BitcoinSerializer
/**
 * Constructs a BitcoinSerializer with the given behavior.
 *
 * @param params           networkParams used to create Messages instances and termining packetMagic
 * @param parseRetain      retain the backing byte array of a message for fast reserialization.
 */
(
        /**
         * Get the network parameters for this serializer.
         */
        val parameters: NetworkParameters,
        /**
         * Whether the serializer will produce cached mode Messages
         */
        override val isParseRetainMode: Boolean) : MessageSerializer() {

    /**
     * Writes message to to the output stream.
     */
    @Throws(IOException::class)
    override fun serialize(name: String, message: ByteArray, out: OutputStream) {
        val header = ByteArray(4 + COMMAND_LEN + 4 + 4 /* checksum */)
        uint32ToByteArrayBE(parameters.packetMagic, header, 0)

        // The header array is initialized to zero by Java so we don't have to worry about
        // NULL terminating the string here.
        var i = 0
        while (i < name.length && i < COMMAND_LEN) {
            header[4 + i] = (name.codePointAt(i) and 0xFF).toByte()
            i++
        }

        Utils.uint32ToByteArrayLE(message.size.toLong(), header, 4 + COMMAND_LEN)

        val hash = Sha256Hash.hashTwice(message)
        System.arraycopy(hash, 0, header, 4 + COMMAND_LEN + 4, 4)
        out.write(header)
        out.write(message)

        if (log.isDebugEnabled())
            log.debug("Sending {} message: {}", name, HEX.encode(header) + HEX.encode(message))
    }

    /**
     * Writes message to to the output stream.
     */
    @Throws(IOException::class)
    override fun serialize(message: Message, out: OutputStream) {
        val name = names[message.javaClass] ?: throw Error("BitcoinSerializer doesn't currently know how to serialize " + message.javaClass)
        serialize(name, message.bitcoinSerialize(), out)
    }

    /**
     * Reads a message from the given ByteBuffer and returns it.
     */
    @Throws(ProtocolException::class, IOException::class)
    override fun deserialize(`in`: ByteBuffer): Message {
        // A Bitcoin protocol message has the following format.
        //
        //   - 4 byte magic number: 0xfabfb5da for the testnet or
        //                          0xf9beb4d9 for production
        //   - 12 byte command in ASCII
        //   - 4 byte payload size
        //   - 4 byte checksum
        //   - Payload data
        //
        // The checksum is the first 4 bytes of a SHA256 hash of the message payload. It isn't
        // present for all messages, notably, the first one on a connection.
        //
        // Bitcoin Core ignores garbage before the magic header bytes. We have to do the same because
        // sometimes it sends us stuff that isn't part of any message.
        seekPastMagicBytes(`in`)
        val header = BitcoinPacketHeader(`in`)
        // Now try to read the whole message.
        return deserializePayload(header, `in`)
    }

    /**
     * Deserializes only the header in case packet meta data is needed before decoding
     * the payload. This method assumes you have already called seekPastMagicBytes()
     */
    @Throws(ProtocolException::class, IOException::class)
    override fun deserializeHeader(`in`: ByteBuffer): BitcoinPacketHeader {
        return BitcoinPacketHeader(`in`)
    }

    /**
     * Deserialize payload only.  You must provide a header, typically obtained by calling
     * [BitcoinSerializer.deserializeHeader].
     */
    @Throws(ProtocolException::class, BufferUnderflowException::class)
    override fun deserializePayload(header: BitcoinPacketHeader, `in`: ByteBuffer): Message {
        val payloadBytes = ByteArray(header.size)
        `in`.get(payloadBytes, 0, header.size)

        // Verify the checksum.
        val hash: ByteArray
        hash = Sha256Hash.hashTwice(payloadBytes)
        if (header.checksum[0] != hash[0] || header.checksum[1] != hash[1] ||
                header.checksum[2] != hash[2] || header.checksum[3] != hash[3]) {
            throw ProtocolException("Checksum failed to verify, actual " +
                    HEX.encode(hash) +
                    " vs " + HEX.encode(header.checksum))
        }

        if (log.isDebugEnabled()) {
            log.debug("Received {} byte '{}' message: {}", header.size, header.command,
                    HEX.encode(payloadBytes))
        }

        try {
            return makeMessage(header.command, header.size, payloadBytes, hash, header.checksum)
        } catch (e: Exception) {
            throw ProtocolException("Error deserializing message " + HEX.encode(payloadBytes) + "\n", e)
        }

    }

    @Throws(ProtocolException::class)
    private fun makeMessage(command: String, length: Int, payloadBytes: ByteArray, hash: ByteArray, checksum: ByteArray): Message {
        // We use an if ladder rather than reflection because reflection is very slow on Android.
        val message: Message
        if (command == "version") {
            return VersionMessage(parameters, payloadBytes)
        } else if (command == "inv") {
            message = makeInventoryMessage(payloadBytes, length)
        } else if (command == "block") {
            message = makeBlock(payloadBytes, length)
        } else if (command == "merkleblock") {
            message = makeFilteredBlock(payloadBytes)
        } else if (command == "getdata") {
            message = GetDataMessage(parameters, payloadBytes, this, length)
        } else if (command == "getblocks") {
            message = GetBlocksMessage(parameters, payloadBytes)
        } else if (command == "getheaders") {
            message = GetHeadersMessage(parameters, payloadBytes)
        } else if (command == "tx") {
            message = makeTransaction(payloadBytes, 0, length, hash)
        } else if (command == "addr") {
            message = makeAddressMessage(payloadBytes, length)
        } else if (command == "ping") {
            message = Ping(parameters, payloadBytes)
        } else if (command == "pong") {
            message = Pong(parameters, payloadBytes)
        } else if (command == "verack") {
            return VersionAck(parameters, payloadBytes)
        } else if (command == "headers") {
            return HeadersMessage(parameters, payloadBytes)
        } else if (command == "alert") {
            return makeAlertMessage(payloadBytes)
        } else if (command == "filterload") {
            return makeBloomFilter(payloadBytes)
        } else if (command == "notfound") {
            return NotFoundMessage(parameters, payloadBytes)
        } else if (command == "mempool") {
            return MemoryPoolMessage()
        } else if (command == "reject") {
            return RejectMessage(parameters, payloadBytes)
        } else if (command == "utxos") {
            return UTXOsMessage(parameters, payloadBytes)
        } else if (command == "getutxos") {
            return GetUTXOsMessage(parameters, payloadBytes)
        } else if (command == "sendheaders") {
            return SendHeadersMessage(parameters)
        } else if (command == "feefilter") {
            return FeeFilterMessage(parameters)
        } else {
            log.warn("No support for deserializing message with name {}", command)
            return UnknownMessage(parameters, command, payloadBytes)
        }
        return message
    }

    /**
     * Make an address message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class)
    override fun makeAddressMessage(payloadBytes: ByteArray, length: Int): AddressMessage {
        return AddressMessage(parameters, payloadBytes, this, length)
    }

    /**
     * Make an alert message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class)
    override fun makeAlertMessage(payloadBytes: ByteArray): Message {
        return AlertMessage(parameters, payloadBytes)
    }

    /**
     * Make a block from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class)
    override fun makeBlock(payloadBytes: ByteArray, offset: Int, length: Int): Block {
        return Block(parameters, payloadBytes, offset, this, length)
    }

    /**
     * Make an filter message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class)
    override fun makeBloomFilter(payloadBytes: ByteArray): Message {
        return BloomFilter(parameters, payloadBytes)
    }

    /**
     * Make a filtered block from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class)
    override fun makeFilteredBlock(payloadBytes: ByteArray): FilteredBlock {
        return FilteredBlock(parameters, payloadBytes)
    }

    /**
     * Make an inventory message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class)
    override fun makeInventoryMessage(payloadBytes: ByteArray, length: Int): InventoryMessage {
        return InventoryMessage(parameters, payloadBytes, this, length)
    }

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class)
    override fun makeTransaction(payloadBytes: ByteArray, offset: Int,
                                 length: Int, hash: ByteArray?): Transaction {
        val tx = Transaction(parameters, payloadBytes, offset, null, this, length)
        if (hash != null)
            tx.hash = Sha256Hash.wrapReversed(hash)
        return tx
    }

    @Throws(BufferUnderflowException::class)
    override fun seekPastMagicBytes(`in`: ByteBuffer) {
        var magicCursor = 3  // Which byte of the magic we're looking for currently.
        while (true) {
            val b = `in`.get()
            // We're looking for a run of bytes that is the same as the packet magic but we want to ignore partial
            // magics that aren't complete. So we keep track of where we're up to with magicCursor.
            val expectedByte = (0xFF and parameters.packetMagic.ushr(magicCursor * 8)).toByte()
            if (b == expectedByte) {
                magicCursor--
                if (magicCursor < 0) {
                    // We found the magic sequence.
                    return
                } else {
                    // We still have further to go to find the next message.
                }
            } else {
                magicCursor = 3
            }
        }
    }


    class BitcoinPacketHeader @Throws(ProtocolException::class, BufferUnderflowException::class)
    constructor(`in`: ByteBuffer) {

        val header: ByteArray
        val command: String
        val size: Int
        val checksum: ByteArray

        init {
            header = ByteArray(HEADER_LENGTH)
            `in`.get(header, 0, header.size)

            var cursor = 0

            // The command is a NULL terminated string, unless the command fills all twelve bytes
            // in which case the termination is implicit.
            while (header[cursor].toInt() != 0 && cursor < COMMAND_LEN) {
                cursor++
            }
            val commandBytes = ByteArray(cursor)
            System.arraycopy(header, 0, commandBytes, 0, cursor)
            command = Utils.toString(commandBytes, "US-ASCII")
            cursor = COMMAND_LEN

            size = readUint32(header, cursor).toInt()
            cursor += 4

            if (size > Message.MAX_SIZE || size < 0)
                throw ProtocolException("Message size too large: " + size)

            // Old clients don't send the checksum.
            checksum = ByteArray(4)
            // Note that the size read above includes the checksum bytes.
            System.arraycopy(header, cursor, checksum, 0, 4)
            cursor += 4
        }

        companion object {
            /** The largest number of bytes that a header can represent  */
            val HEADER_LENGTH = COMMAND_LEN + 4 + 4
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(BitcoinSerializer::class.java!!)
        private val COMMAND_LEN = 12

        private val names = HashMap<Class<out Message>, String>()

        init {
            names.put(VersionMessage::class.java, "version")
            names.put(InventoryMessage::class.java, "inv")
            names.put(Block::class.java, "block")
            names.put(GetDataMessage::class.java, "getdata")
            names.put(Transaction::class.java, "tx")
            names.put(AddressMessage::class.java, "addr")
            names.put(Ping::class.java, "ping")
            names.put(Pong::class.java, "pong")
            names.put(VersionAck::class.java, "verack")
            names.put(GetBlocksMessage::class.java, "getblocks")
            names.put(GetHeadersMessage::class.java, "getheaders")
            names.put(GetAddrMessage::class.java, "getaddr")
            names.put(HeadersMessage::class.java, "headers")
            names.put(BloomFilter::class.java, "filterload")
            names.put(FilteredBlock::class.java, "merkleblock")
            names.put(NotFoundMessage::class.java, "notfound")
            names.put(MemoryPoolMessage::class.java, "mempool")
            names.put(RejectMessage::class.java, "reject")
            names.put(GetUTXOsMessage::class.java, "getutxos")
            names.put(UTXOsMessage::class.java, "utxos")
        }
    }
}
