/*
 * Copyright 2011 Steve Coughlan.
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
 * Parent class for header only messages that don't have a payload.
 * Currently this includes getaddr, verack and special bitcoinj class UnknownMessage.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
abstract class EmptyMessage : Message {

    constructor() {
        length = 0
    }

    constructor(params: NetworkParameters) : super(params) {
        length = 0
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray, offset: Int) : super(params, payload, offset) {
        length = 0
    }

    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
    }

    @Throws(ProtocolException::class)
    override fun parse() {
    }

    /* (non-Javadoc)
      * @see Message#bitcoinSerialize()
      */
    override fun bitcoinSerialize(): ByteArray {
        return ByteArray(0)
    }
}
