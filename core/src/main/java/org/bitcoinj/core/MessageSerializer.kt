/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2015 Ross Nicoll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core

import java.io.IOException
import java.io.OutputStream
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer

/**
 * Generic interface for classes which serialize/deserialize messages. Implementing
 * classes should be immutable.
 */
abstract class MessageSerializer {

    /**
     * Whether the serializer will produce cached mode Messages
     */
    abstract val isParseRetainMode: Boolean

    /**
     * Reads a message from the given ByteBuffer and returns it.
     */
    @Throws(ProtocolException::class, IOException::class, UnsupportedOperationException::class)
    abstract fun deserialize(`in`: ByteBuffer): Message

    /**
     * Deserializes only the header in case packet meta data is needed before decoding
     * the payload. This method assumes you have already called seekPastMagicBytes()
     */
    @Throws(ProtocolException::class, IOException::class, UnsupportedOperationException::class)
    abstract fun deserializeHeader(`in`: ByteBuffer): BitcoinSerializer.BitcoinPacketHeader

    /**
     * Deserialize payload only.  You must provide a header, typically obtained by calling
     * [BitcoinSerializer.deserializeHeader].
     */
    @Throws(ProtocolException::class, BufferUnderflowException::class, UnsupportedOperationException::class)
    abstract fun deserializePayload(header: BitcoinSerializer.BitcoinPacketHeader, `in`: ByteBuffer): Message

    /**
     * Make an address message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class, UnsupportedOperationException::class)
    abstract fun makeAddressMessage(payloadBytes: ByteArray, length: Int): AddressMessage

    /**
     * Make an alert message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class, UnsupportedOperationException::class)
    abstract fun makeAlertMessage(payloadBytes: ByteArray): Message


    /**
     * Make a block from the payload, using an offset of zero and the payload
     * length as block length.
     */
    @Throws(ProtocolException::class)
    fun makeBlock(payloadBytes: ByteArray): Block {
        return makeBlock(payloadBytes, 0, payloadBytes.size)
    }

    /**
     * Make a block from the payload, using an offset of zero and the provided
     * length as block length.
     */
    @Throws(ProtocolException::class)
    fun makeBlock(payloadBytes: ByteArray, length: Int): Block {
        return makeBlock(payloadBytes, 0, length)
    }

    /**
     * Make a block from the payload, using an offset of zero and the provided
     * length as block length. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class, UnsupportedOperationException::class)
    abstract fun makeBlock(payloadBytes: ByteArray, offset: Int, length: Int): Block

    /**
     * Make an filter message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class, UnsupportedOperationException::class)
    abstract fun makeBloomFilter(payloadBytes: ByteArray): Message

    /**
     * Make a filtered block from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class, UnsupportedOperationException::class)
    abstract fun makeFilteredBlock(payloadBytes: ByteArray): FilteredBlock

    /**
     * Make an inventory message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Throws(ProtocolException::class, UnsupportedOperationException::class)
    abstract fun makeInventoryMessage(payloadBytes: ByteArray, length: Int): InventoryMessage

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     *
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    @Throws(ProtocolException::class, UnsupportedOperationException::class)
    abstract fun makeTransaction(payloadBytes: ByteArray, offset: Int, length: Int, hash: ByteArray?): Transaction

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     *
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    @Throws(ProtocolException::class)
    @JvmOverloads
    fun makeTransaction(payloadBytes: ByteArray, offset: Int = 0): Transaction {
        return makeTransaction(payloadBytes, offset, payloadBytes.size, null)
    }

    @Throws(BufferUnderflowException::class)
    abstract fun seekPastMagicBytes(`in`: ByteBuffer)

    /**
     * Writes message to to the output stream.
     *
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support serialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support serializing the given message.
     */
    @Throws(IOException::class, UnsupportedOperationException::class)
    abstract fun serialize(name: String, message: ByteArray, out: OutputStream)

    /**
     * Writes message to to the output stream.
     *
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support serialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support serializing the given message.
     */
    @Throws(IOException::class, UnsupportedOperationException::class)
    abstract fun serialize(message: Message, out: OutputStream)

}
/**
 * Make a transaction from the payload. Extension point for alternative
 * serialization format support.
 *
 * @throws UnsupportedOperationException if this serializer/deserializer
 * does not support deserialization. This can occur either because it's a dummy
 * serializer (i.e. for messages with no network parameters), or because
 * it does not support deserializing transactions.
 */
