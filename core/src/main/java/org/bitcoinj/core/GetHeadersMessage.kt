/*
 * Copyright 2011 Google Inc.
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
 * The "getheaders" command is structurally identical to "getblocks", but has different meaning. On receiving this
 * message a Bitcoin node returns matching blocks up to the limit, but without the bodies. It is useful as an
 * optimization: when your wallet does not contain any keys created before a particular time, you don't have to download
 * the bodies for those blocks because you know there are no relevant transactions.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class GetHeadersMessage : GetBlocksMessage {
    constructor(params: NetworkParameters, locator: MutableList<Sha256Hash>, stopHash: Sha256Hash) : super(params, locator, stopHash) {}

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray) : super(params, payload) {
    }

    override fun toString(): String {
        return "getheaders: " + Utils.join(locator)
    }

    /**
     * Compares two getheaders messages. Note that even though they are structurally identical a GetHeadersMessage
     * will not compare equal to a GetBlocksMessage containing the same data.
     */
    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as GetHeadersMessage?
        return version == other!!.version && stopHash == other.stopHash &&
                locator.size == other.locator.size && locator.containsAll(other.locator)  // ignores locator ordering
    }

    override fun hashCode(): Int {
        var hashCode = version.toInt() xor "getheaders".hashCode() xor stopHash.hashCode()
        for (aLocator in locator) hashCode = hashCode xor aLocator.hashCode() // ignores locator ordering
        return hashCode
    }
}
