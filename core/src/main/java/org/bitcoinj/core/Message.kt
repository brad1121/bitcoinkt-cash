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

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.*
import java.math.BigInteger
import java.util.Arrays

import com.google.common.base.Preconditions.checkState

/**
 *
 * A Message is a data structure that can be serialized/deserialized using the Bitcoin serialization format.
 * Specific types of messages that are used both in the block chain, and on the wire, are derived from this
 * class.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
abstract class Message {

    // The offset is how many bytes into the provided byte array this message payload starts at.
    protected var offset: Int = 0
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message payload.
    protected var cursor: Int = 0

    var length = UNKNOWN_LENGTH

    // The raw message payload bytes themselves.
    protected var payload: ByteArray? = null

    var isRecached = false
        protected set
    protected var serializer: MessageSerializer

    protected var protocolVersion: Int = 0

    /** Network parameters this message was created with.  */
    var params: NetworkParameters? = null

    /**
     * used for unit testing
     */
    val isCached: Boolean
        get() = payload != null

    /**
     * This method is a NOP for all classes except Block and Transaction.  It is only declared in Message
     * so BitcoinSerializer can avoid 2 instanceof checks + a casting.
     */
    val hash: Sha256Hash
        get() = throw UnsupportedOperationException()

    /**
     * This returns a correct value by parsing the message.
     */
    val messageSize: Int
        get() {
            if (length == UNKNOWN_LENGTH)
                checkState(false, "Length field has not been set in %s.", javaClass.getSimpleName())
            return length
        }

    protected constructor() {
        serializer = DummySerializer.DEFAULT
    }

    protected constructor(params: NetworkParameters) {
        this.params = params
        serializer = params.getDefaultSerializer()
    }

    /**
     *
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @param serializer the serializer to use for this message.
     * @param length The length of message payload if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    @JvmOverloads protected constructor(params: NetworkParameters, payload: ByteArray, offset: Int, protocolVersion: Int = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT), serializer: MessageSerializer = params.getDefaultSerializer(), length: Int = UNKNOWN_LENGTH) {
        this.serializer = serializer
        this.protocolVersion = protocolVersion
        this.params = params
        this.payload = payload
        this.offset = offset
        this.cursor = this.offset
        this.length = length

        parse()

        if (this.length == UNKNOWN_LENGTH)
            checkState(false, "Length field has not been set in constructor for %s after parse.",
                    javaClass.getSimpleName())

        if (SELF_CHECK) {
            selfCheck(payload, offset)
        }

        if (!serializer.isParseRetainMode)
            this.payload = null
    }

    private fun selfCheck(payload: ByteArray, offset: Int) {
        if (this !is VersionMessage) {
            val payloadBytes = ByteArray(cursor - offset)
            System.arraycopy(payload, offset, payloadBytes, 0, cursor - offset)
            val reserialized = bitcoinSerialize()
            if (!Arrays.equals(reserialized, payloadBytes))
                throw RuntimeException("Serialization is wrong: \n" +
                        Utils.HEX.encode(reserialized) + " vs \n" +
                        Utils.HEX.encode(payloadBytes))
        }
    }

    @Throws(ProtocolException::class)
    protected constructor(params: NetworkParameters, payload: ByteArray, offset: Int, serializer: MessageSerializer?, length: Int) : this(params, payload, offset, params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT),
            serializer, length) {
    }

    // These methods handle the serialization/deserialization using the custom Bitcoin protocol.

    @Throws(ProtocolException::class)
    protected abstract fun parse()

    /**
     *
     * To be called before any change of internal values including any setters. This ensures any cached byte array is
     * removed.
     *
     *
     *
     * Child messages of this object(e.g. Transactions belonging to a Block) will not have their internal byte caches
     * invalidated unless they are also modified internally.
     */
    open fun unCache() {
        payload = null
        isRecached = false
    }

    open fun adjustLength(newArraySize: Int, adjustment: Int) {
        if (length == UNKNOWN_LENGTH)
            return
        // Our own length is now unknown if we have an unknown length adjustment.
        if (adjustment == UNKNOWN_LENGTH) {
            length = UNKNOWN_LENGTH
            return
        }
        length += adjustment
        // Check if we will need more bytes to encode the length prefix.
        if (newArraySize == 1)
            length++  // The assumption here is we never call adjustLength with the same arraySize as before.
        else if (newArraySize != 0)
            length += VarInt.sizeOf(newArraySize.toLong()) - VarInt.sizeOf((newArraySize - 1).toLong())
    }

    /**
     * Returns a copy of the array returned by [Message.unsafeBitcoinSerialize], which is safe to mutate.
     * If you need extra performance and can guarantee you won't write to the array, you can use the unsafe version.
     *
     * @return a freshly allocated serialized byte array
     */
    open fun bitcoinSerialize(): ByteArray {
        val bytes = unsafeBitcoinSerialize()
        val copy = ByteArray(bytes.size)
        System.arraycopy(bytes, 0, copy, 0, bytes.size)
        return copy
    }

    /**
     * Serialize this message to a byte array that conforms to the bitcoin wire protocol.
     * <br></br>
     * This method may return the original byte array used to construct this message if the
     * following conditions are met:
     *
     *  1. 1) The message was parsed from a byte array with parseRetain = true
     *  1. 2) The message has not been modified
     *  1. 3) The array had an offset of 0 and no surplus bytes
     *
     *
     * If condition 3 is not met then an copy of the relevant portion of the array will be returned.
     * Otherwise a full serialize will occur. For this reason you should only use this API if you can guarantee you
     * will treat the resulting array as read only.
     *
     * @return a byte array owned by this object, do NOT mutate it.
     */
    fun unsafeBitcoinSerialize(): ByteArray {
        // 1st attempt to use a cached array.
        if (payload != null) {
            if (offset == 0 && length == payload!!.size) {
                // Cached byte array is the entire message with no extras so we can return as is and avoid an array
                // copy.
                return payload
            }

            val buf = ByteArray(length)
            System.arraycopy(payload!!, offset, buf, 0, length)
            return buf
        }

        // No cached array available so serialize parts by stream.
        val stream = UnsafeByteArrayOutputStream(if (length < 32) 32 else length + 32)
        try {
            bitcoinSerializeToStream(stream)
        } catch (e: IOException) {
            // Cannot happen, we are serializing to a memory stream.
        }

        if (serializer.isParseRetainMode) {
            // A free set of steak knives!
            // If there happens to be a call to this method we gain an opportunity to recache
            // the byte array and in this case it contains no bytes from parent messages.
            // This give a dual benefit.  Releasing references to the larger byte array so that it
            // it is more likely to be GC'd.  And preventing double serializations.  E.g. calculating
            // merkle root calls this method.  It is will frequently happen prior to serializing the block
            // which means another call to bitcoinSerialize is coming.  If we didn't recache then internal
            // serialization would occur a 2nd time and every subsequent time the message is serialized.
            payload = stream.toByteArray()
            cursor = cursor - offset
            offset = 0
            isRecached = true
            length = payload!!.size
            return payload
        }
        // Record length. If this Message wasn't parsed from a byte stream it won't have length field
        // set (except for static length message types).  Setting it makes future streaming more efficient
        // because we can preallocate the ByteArrayOutputStream buffer and avoid resizing.
        val buf = stream.toByteArray()
        length = buf.size
        return buf
    }

    /**
     * Serialize this message to the provided OutputStream using the bitcoin wire format.
     *
     * @param stream
     * @throws IOException
     */
    @Throws(IOException::class)
    fun bitcoinSerialize(stream: OutputStream) {
        // 1st check for cached bytes.
        if (payload != null && length != UNKNOWN_LENGTH) {
            stream.write(payload!!, offset, length)
            return
        }

        bitcoinSerializeToStream(stream)
    }

    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
     */
    @Throws(IOException::class)
    protected open fun bitcoinSerializeToStream(stream: OutputStream) {
        log.error("Error: {} class has not implemented bitcoinSerializeToStream method.  Generating message with no payload", javaClass)
    }

    @Throws(ProtocolException::class)
    protected fun readUint32(): Long {
        try {
            val u = Utils.readUint32(payload!!, cursor)
            cursor += 4
            return u
        } catch (e: ArrayIndexOutOfBoundsException) {
            throw ProtocolException(e)
        }

    }

    @Throws(ProtocolException::class)
    protected fun readInt64(): Long {
        try {
            val u = Utils.readInt64(payload!!, cursor)
            cursor += 8
            return u
        } catch (e: ArrayIndexOutOfBoundsException) {
            throw ProtocolException(e)
        }

    }

    @Throws(ProtocolException::class)
    protected fun readUint64(): BigInteger {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        return BigInteger(Utils.reverseBytes(readBytes(8)))
    }

    @Throws(ProtocolException::class)
    @JvmOverloads protected fun readVarInt(offset: Int = 0): Long {
        try {
            val varint = VarInt(payload!!, cursor + offset)
            cursor += offset + varint.originalSizeInBytes
            return varint.value
        } catch (e: ArrayIndexOutOfBoundsException) {
            throw ProtocolException(e)
        }

    }

    @Throws(ProtocolException::class)
    protected fun readBytes(length: Int): ByteArray {
        if (length > MAX_SIZE) {
            throw ProtocolException("Claimed value length too large: " + length)
        }
        try {
            val b = ByteArray(length)
            System.arraycopy(payload!!, cursor, b, 0, length)
            cursor += length
            return b
        } catch (e: IndexOutOfBoundsException) {
            throw ProtocolException(e)
        }

    }

    @Throws(ProtocolException::class)
    protected fun readByteArray(): ByteArray {
        val len = readVarInt()
        return readBytes(len.toInt())
    }

    @Throws(ProtocolException::class)
    protected fun readStr(): String {
        val length = readVarInt()
        return if (length == 0L) "" else Utils.toString(readBytes(length.toInt()), "UTF-8") // optimization for empty strings
    }

    @Throws(ProtocolException::class)
    protected fun readHash(): Sha256Hash {
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        return Sha256Hash.wrapReversed(readBytes(32))
    }

    protected fun hasMoreBytes(): Boolean {
        return cursor < payload!!.size
    }

    /**
     * Set the serializer for this message when deserialized by Java.
     */
    @Throws(IOException::class, ClassNotFoundException::class)
    private fun readObject(`in`: java.io.ObjectInputStream) {
        `in`.defaultReadObject()
        if (null != params) {
            this.serializer = params!!.getDefaultSerializer()
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(Message::class.java!!)

        val MAX_SIZE = 0x02000000 // 32MB

        val UNKNOWN_LENGTH = Integer.MIN_VALUE

        // Useful to ensure serialize/deserialize are consistent with each other.
        private val SELF_CHECK = false
    }
}
