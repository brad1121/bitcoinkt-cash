/*
 * Copyright 2011 Noa Resare
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

import java.io.IOException
import java.io.OutputStream

/**
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class Ping : Message {
    var nonce: Long = 0
        private set
    private var hasNonce: Boolean = false

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray) : super(params, payloadBytes, 0) {
    }

    /**
     * Create a Ping with a nonce value.
     * Only use this if the remote node has a protocol version > 60000
     */
    constructor(nonce: Long) {
        this.nonce = nonce
        this.hasNonce = true
    }

    /**
     * Create a Ping without a nonce value.
     * Only use this if the remote node has a protocol version <= 60000
     */
    constructor() {
        this.hasNonce = false
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(stream: OutputStream) {
        if (hasNonce)
            Utils.int64ToByteStreamLE(nonce, stream)
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        try {
            nonce = readInt64()
            hasNonce = true
        } catch (e: ProtocolException) {
            hasNonce = false
        }

        length = if (hasNonce) 8 else 0
    }

    fun hasNonce(): Boolean {
        return hasNonce
    }
}
