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

/**
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class UnknownMessage @Throws(ProtocolException::class)
constructor(params: NetworkParameters, private val name: String, payloadBytes: ByteArray) : EmptyMessage(params, payloadBytes, 0) {

    override fun toString(): String {
        return "Unknown message [" + name + "]: " + if (payload == null) "" else Utils.HEX.encode(payload!!)
    }
}
