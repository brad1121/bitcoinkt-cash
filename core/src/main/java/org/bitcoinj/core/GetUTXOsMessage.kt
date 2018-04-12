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
import com.google.common.collect.ImmutableList

import java.io.IOException
import java.io.OutputStream

/**
 *
 * This command is supported only by [Bitcoin XT](http://github.com/bitcoinxt/bitcoinxt) nodes, which
 * advertise themselves using the second service bit flag. It requests a query of the UTXO set keyed by a set of
 * outpoints (i.e. tx hash and output index). The result contains a bitmap of spentness flags, and the contents of
 * the associated outputs if they were found. The results aren't authenticated by anything, so the peer could lie,
 * or a man in the middle could swap out its answer for something else. Please consult
 * [BIP 65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki) for more information on this
 * message.
 *
 *
 * Note that this message does not let you query the UTXO set by address, script or any other criteria. The
 * reason is that Bitcoin nodes don't calculate the necessary database indexes to answer such queries, to save
 * space and time. If you want to look up unspent outputs by address, you can either query a block explorer site,
 * or you can use the [FullPrunedBlockChain] class to build the required indexes yourself. Bear in that it will
 * be quite slow and disk intensive to do that!
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class GetUTXOsMessage : Message {

    var includeMempool: Boolean = false
        private set
    var outPoints: ImmutableList<TransactionOutPoint>? = null
        private set

    constructor(params: NetworkParameters, outPoints: List<TransactionOutPoint>, includeMempool: Boolean) : super(params) {
        this.outPoints = ImmutableList.copyOf(outPoints)
        this.includeMempool = includeMempool
    }

    constructor(params: NetworkParameters, payloadBytes: ByteArray) : super(params, payloadBytes, 0) {}

    @Throws(ProtocolException::class)
    override fun parse() {
        includeMempool = readBytes(1)[0].toInt() == 1
        val numOutpoints = readVarInt()
        val list = ImmutableList.builder<TransactionOutPoint>()
        for (i in 0 until numOutpoints) {
            val outPoint = TransactionOutPoint(params!!, payload!!, cursor)
            list.add(outPoint)
            cursor += outPoint.messageSize
        }
        outPoints = list.build()
        length = cursor
    }

    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
        stream.write(byteArrayOf(if (includeMempool) 1.toByte() else 0))  // include mempool.
        stream.write(VarInt(outPoints!!.size.toLong()).encode())
        for (outPoint in outPoints!!) {
            outPoint.bitcoinSerializeToStream(stream)
        }
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as GetUTXOsMessage?
        return includeMempool == other!!.includeMempool && outPoints == other.outPoints
    }

    override fun hashCode(): Int {
        return Objects.hashCode(includeMempool, outPoints)
    }

    companion object {
        val MIN_PROTOCOL_VERSION = 70002
        /** Bitmask of service flags required for a node to support this command (0x3)  */
        val SERVICE_FLAGS_REQUIRED: Long = 3
    }
}
