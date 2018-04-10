/*
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
 * Dummy serializer used ONLY for objects which do not have network parameters
 * set.
 */
internal class DummySerializer : MessageSerializer() {

    override val isParseRetainMode: Boolean
        get() = false

    @Throws(UnsupportedOperationException::class)
    override fun deserialize(`in`: ByteBuffer): Message {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun deserializeHeader(`in`: ByteBuffer): BitcoinSerializer.BitcoinPacketHeader {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun deserializePayload(header: BitcoinSerializer.BitcoinPacketHeader, `in`: ByteBuffer): Message {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun makeAddressMessage(payloadBytes: ByteArray, length: Int): AddressMessage {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun makeAlertMessage(payloadBytes: ByteArray): Message {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun makeBlock(payloadBytes: ByteArray, offset: Int, length: Int): Block {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun makeBloomFilter(payloadBytes: ByteArray): Message {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun makeFilteredBlock(payloadBytes: ByteArray): FilteredBlock {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun makeInventoryMessage(payloadBytes: ByteArray, length: Int): InventoryMessage {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(UnsupportedOperationException::class)
    override fun makeTransaction(payloadBytes: ByteArray, offset: Int, length: Int, hash: ByteArray?): Transaction {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(BufferUnderflowException::class)
    override fun seekPastMagicBytes(`in`: ByteBuffer) {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(IOException::class)
    override fun serialize(name: String, message: ByteArray, out: OutputStream) {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    @Throws(IOException::class)
    override fun serialize(message: Message, out: OutputStream) {
        throw UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE)
    }

    companion object {
        val DEFAULT = DummySerializer()

        private val DEFAULT_EXCEPTION_MESSAGE = "Dummy serializer cannot serialize/deserialize objects as it does not know which network they belong to."
    }

}
