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

import java.io.IOException
import java.io.OutputStream
import java.util.ArrayList

/**
 *
 * Represents the "getblocks" P2P network message, which requests the hashes of the parts of the block chain we're
 * missing. Those blocks can then be downloaded with a [GetDataMessage].
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
open class GetBlocksMessage : Message {

    protected var version: Long = 0
    protected var locator: MutableList<Sha256Hash>? = null
        get(): MutableList<Sha256Hash>? {
        return locator
    }
    lateinit var stopHash: Sha256Hash
        protected set

    constructor(params: NetworkParameters, locator: MutableList<Sha256Hash>, stopHash: Sha256Hash) : super(params) {
        this.version = protocolVersion.toLong()
        this.locator = locator
        this.stopHash = stopHash
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray) : super(params, payload, 0) {
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        cursor = offset
        version = readUint32()
        val startCount = readVarInt().toInt()
        if (startCount > 500)
            throw ProtocolException("Number of locators cannot be > 500, received: " + startCount)
        length = cursor - offset + (startCount + 1) * 32
        locator = ArrayList(startCount)
        for (i in 0 until startCount) {
            locator!!.add(readHash())
        }
        stopHash = readHash()
    }



    override fun toString(): String {
        return "getblocks: " + Utils.join(locator!!)
    }

    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
        // Version, for some reason.
        Utils.uint32ToByteStreamLE(params!!.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT).toLong(), stream)
        // Then a vector of block hashes. This is actually a "block locator", a set of block
        // identifiers that spans the entire chain with exponentially increasing gaps between
        // them, until we end up at the genesis block. See CBlockLocator::Set()
        stream.write(VarInt(locator!!.size.toLong()).encode())
        for (hash in locator!!) {
            // Have to reverse as wire format is little endian.
            stream.write(hash.reversedBytes)
        }
        // Next, a block ID to stop at.
        stream.write(stopHash.reversedBytes)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as GetBlocksMessage?
        return version == other!!.version && stopHash == other.stopHash &&
                locator!!.size == other.locator!!.size && locator!!.containsAll(other.locator!!) // ignores locator ordering
    }

    override fun hashCode(): Int {
        var hashCode = version.toInt() xor "getblocks".hashCode() xor stopHash.hashCode()
        for (aLocator in locator!!) hashCode = hashCode xor aLocator.hashCode() // ignores locator ordering
        return hashCode
    }
}
