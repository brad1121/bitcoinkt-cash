/*
 * Copyright 2014 the bitcoinj authors
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

import com.google.common.base.Objects
import java.io.IOException
import java.io.OutputStream
import java.util.ArrayList
import java.util.Arrays

/**
 *
 * Message representing a list of unspent transaction outputs ("utxos"), returned in response to sending a
 * [GetUTXOsMessage] ("getutxos"). Note that both this message and the query that generates it are not
 * supported by Bitcoin Core. An implementation is available in [Bitcoin XT](https://github.com/bitcoinxt/bitcoinxt),
 * a patch set on top of Core. Thus if you want to use it, you must find some XT peers to connect to. This can be done
 * using a [org.bitcoinj.net.discovery.HttpDiscovery] class combined with an HTTP/Cartographer seed.
 *
 *
 * The getutxos/utxos protocol is defined in [BIP 65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki).
 * In that document you can find a discussion of the security of this protocol (briefly, there is none). Because the
 * data found in this message is not authenticated it should be used carefully. Places where it can be useful are if
 * you're querying your own trusted node, if you're comparing answers from multiple nodes simultaneously and don't
 * believe there is a MITM on your connection, or if you're only using the returned data as a UI hint and it's OK
 * if the data is occasionally wrong. Bear in mind that the answer can be wrong even in the absence of malicious intent
 * just through the nature of querying an ever changing data source: the UTXO set may be updated by a new transaction
 * immediately after this message is returned.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class UTXOsMessage : Message {
    private var height: Long = 0
    private var chainHead: Sha256Hash? = null
    private var hits: ByteArray? = null   // little-endian bitset indicating whether an output was found or not.

    private var outputs: MutableList<TransactionOutput>? = null
    private var heights: LongArray? = null

    /**
     * Returns a bit map indicating which of the queried outputs were found in the UTXO set.
     */
    val hitMap: ByteArray
        get() = Arrays.copyOf(hits!!, hits!!.size)

    constructor(params: NetworkParameters, payloadBytes: ByteArray) : super(params, payloadBytes, 0) {}

    /**
     * Provide an array of output objects, with nulls indicating that the output was missing. The bitset will
     * be calculated from this.
     */
    constructor(params: NetworkParameters, outputs: List<TransactionOutput>, heights: LongArray, chainHead: Sha256Hash, height: Long) : super(params) {
        hits = ByteArray(Math.ceil(outputs.size / 8.0).toInt())
        for (i in outputs.indices) {
            if (outputs[i] != null)
                Utils.setBitLE(hits!!, i)
        }
        this.outputs = ArrayList(outputs.size)
        for (output in outputs) {
            if (output != null) this.outputs!!.add(output)
        }
        this.chainHead = chainHead
        this.height = height
        this.heights = Arrays.copyOf(heights, heights.size)
    }

    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
        Utils.uint32ToByteStreamLE(height, stream)
        stream.write(chainHead!!.bytes)
        stream.write(VarInt(hits!!.size.toLong()).encode())
        stream.write(hits!!)
        stream.write(VarInt(outputs!!.size.toLong()).encode())
        for (i in outputs!!.indices) {
            val output = outputs!![i]
            val tx = output.parentTransaction
            Utils.uint32ToByteStreamLE(tx?.version ?: 0L, stream)  // Version
            Utils.uint32ToByteStreamLE(heights!![i], stream)  // Height
            output.bitcoinSerializeToStream(stream)
        }
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        // Format is:
        //   uint32 chainHeight
        //   uint256 chainHeadHash
        //   vector<unsigned char> hitsBitmap;
        //   vector<CCoin> outs;
        //
        // A CCoin is  { int nVersion, int nHeight, CTxOut output }
        // The bitmap indicates which of the requested TXOs were found in the UTXO set.
        height = readUint32()
        chainHead = readHash()
        val numBytes = readVarInt().toInt()
        if (numBytes < 0 || numBytes > InventoryMessage.MAX_INVENTORY_ITEMS / 8)
            throw ProtocolException("hitsBitmap out of range: " + numBytes)
        hits = readBytes(numBytes)
        val numOuts = readVarInt().toInt()
        if (numOuts < 0 || numOuts > InventoryMessage.MAX_INVENTORY_ITEMS)
            throw ProtocolException("numOuts out of range: " + numOuts)
        outputs = ArrayList(numOuts)
        heights = LongArray(numOuts)
        for (i in 0 until numOuts) {
            val version = readUint32()
            val height = readUint32()
            if (version > 1)
                throw ProtocolException("Unknown tx version in getutxo output: " + version)
            val output = TransactionOutput(params, null, payload, cursor)
            outputs!!.add(output)
            heights[i] = height
            cursor += output.length
        }
        length = cursor
    }

    /** Returns the list of outputs that matched the query.  */
    fun getOutputs(): List<TransactionOutput> {
        return ArrayList(outputs!!)
    }

    /** Returns the block heights of each output returned in getOutputs(), or MEMPOOL_HEIGHT if not confirmed yet.  */
    fun getHeights(): LongArray {
        return Arrays.copyOf(heights!!, heights!!.size)
    }

    override fun toString(): String {
        return "UTXOsMessage{" +
                "height=" + height +
                ", chainHead=" + chainHead +
                ", hitMap=" + Arrays.toString(hits) +
                ", outputs=" + outputs +
                ", heights=" + Arrays.toString(heights) +
                '}'
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as UTXOsMessage?
        return (height == other!!.height && chainHead == other.chainHead
                && Arrays.equals(heights, other.heights) && Arrays.equals(hits, other.hits)
                && outputs == other.outputs)
    }

    override fun hashCode(): Int {
        return Objects.hashCode(height, chainHead, Arrays.hashCode(heights), Arrays.hashCode(hits), outputs)
    }

    companion object {

        /** This is a special sentinel value that can appear in the heights field if the given tx is in the mempool.  */
        var MEMPOOL_HEIGHT = 0x7FFFFFFFL
    }
}
