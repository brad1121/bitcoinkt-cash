/*
 * Copyright 2011 Google Inc.
 * Copyright 2015 Andreas Schildbach
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

import java.io.IOException
import java.io.OutputStream
import java.util.ArrayList
import java.util.Arrays

/**
 *
 * A protocol message that contains a repeated series of block headers, sent in response to the "getheaders" command.
 * This is useful when you want to traverse the chain but know you don't care about the block contents, for example,
 * because you have a freshly created wallet with no keys.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class HeadersMessage : Message {

    private var blockHeaders: MutableList<Block>? = null

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray) : super(params, payload, 0) {
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, vararg headers: Block) : super(params) {
        blockHeaders = Arrays.asList(*headers)
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, headers: MutableList<Block>) : super(params) {
        blockHeaders = headers
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(stream: OutputStream) {
        stream.write(VarInt(blockHeaders!!.size.toLong()).encode())
        for (header in blockHeaders!!) {
            header.cloneAsHeader().bitcoinSerializeToStream(stream)
            stream.write(0)
        }
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        val numHeaders = readVarInt()
        if (numHeaders > MAX_HEADERS)
            throw ProtocolException("Too many headers: got " + numHeaders + " which is larger than " +
                    MAX_HEADERS)

        blockHeaders = ArrayList()
        val serializer = this.params!!.getSerializer(true)

        for (i in 0 until numHeaders) {
            val newBlockHeader = serializer.makeBlock(payload, cursor, Message.UNKNOWN_LENGTH)
            if (newBlockHeader.hasTransactions()) {
                throw ProtocolException("Block header does not end with a null byte")
            }
            cursor += newBlockHeader.optimalEncodingMessageSize
            blockHeaders!!.add(newBlockHeader)
        }

        if (length == Message.UNKNOWN_LENGTH) {
            length = cursor - offset
        }

        if (log.isDebugEnabled()) {
            for (i in 0 until numHeaders) {
                log.debug(this.blockHeaders!![i].toString())
            }
        }
    }

    fun getBlockHeaders(): List<Block>? {
        return blockHeaders
    }

    companion object {
        private val log = LoggerFactory.getLogger(HeadersMessage::class.java!!)

        // The main client will never send us more than this number of headers.
        val MAX_HEADERS = 2000
    }
}
