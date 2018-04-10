/*
 * Copyright 2012 Matt Corallo
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

import org.bitcoinj.script.Script
import org.bitcoinj.script.ScriptChunk
import com.google.common.base.Objects
import com.google.common.collect.Lists

import java.io.IOException
import java.io.OutputStream
import java.util.ArrayList
import java.util.Arrays

import com.google.common.base.Preconditions.checkArgument
import java.lang.Math.*

/**
 *
 * A Bloom filter is a probabilistic data structure which can be sent to another client so that it can avoid
 * sending us transactions that aren't relevant to our set of keys. This allows for significantly more efficient
 * use of available network bandwidth and CPU time.
 *
 *
 * Because a Bloom filter is probabilistic, it has a configurable false positive rate. So the filter will sometimes
 * match transactions that weren't inserted into it, but it will never fail to match transactions that were. This is
 * a useful privacy feature - if you have spare bandwidth the false positive rate can be increased so the remote peer
 * gets a noisy picture of what transactions are relevant to your wallet.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class BloomFilter : Message {

    private var data: ByteArray? = null
    private var hashFuncs: Long = 0
    private var nTweak: Long = 0
    private var nFlags: Byte = 0

    /**
     * The update flag controls how application of the filter to a block modifies the filter. See the enum javadocs
     * for information on what occurs and when.
     */
    val updateFlag: BloomUpdate
        @Synchronized get() = if (nFlags.toInt() == 0)
            BloomUpdate.UPDATE_NONE
        else if (nFlags.toInt() == 1)
            BloomUpdate.UPDATE_ALL
        else if (nFlags.toInt() == 2)
            BloomUpdate.UPDATE_P2PUBKEY_ONLY
        else
            throw IllegalStateException("Unknown flag combination")

    /** The BLOOM_UPDATE_* constants control when the bloom filter is auto-updated by the peer using
     * it as a filter, either never, for all outputs or only for pay-2-pubkey outputs (default)  */
    enum class BloomUpdate {
        UPDATE_NONE, // 0
        UPDATE_ALL, // 1
        /** Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script  */
        UPDATE_P2PUBKEY_ONLY //2
    }

    /**
     * Construct a BloomFilter by deserializing payloadBytes
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray) : super(params, payloadBytes, 0) {
    }

    /**
     *
     * Constructs a new Bloom Filter which will provide approximately the given false positive rate when the given
     * number of elements have been inserted. If the filter would otherwise be larger than the maximum allowed size,
     * it will be automatically downsized to the maximum size.
     *
     *
     * To check the theoretical false positive rate of a given filter, use
     * [BloomFilter.getFalsePositiveRate].
     *
     *
     * The anonymity of which coins are yours to any peer which you send a BloomFilter to is controlled by the
     * false positive rate. For reference, as of block 187,000, the total number of addresses used in the chain was
     * roughly 4.5 million. Thus, if you use a false positive rate of 0.001 (0.1%), there will be, on average, 4,500
     * distinct public keys/addresses which will be thought to be yours by nodes which have your bloom filter, but
     * which are not actually yours. Keep in mind that a remote node can do a pretty good job estimating the order of
     * magnitude of the false positive rate of a given filter you provide it when considering the anonymity of a given
     * filter.
     *
     *
     * In order for filtered block download to function efficiently, the number of matched transactions in any given
     * block should be less than (with some headroom) the maximum size of the MemoryPool used by the Peer
     * doing the downloading (default is [TxConfidenceTable.MAX_SIZE]). See the comment in processBlock(FilteredBlock)
     * for more information on this restriction.
     *
     *
     * randomNonce is a tweak for the hash function used to prevent some theoretical DoS attacks.
     * It should be a random value, however secureness of the random value is of no great consequence.
     *
     *
     * updateFlag is used to control filter behaviour on the server (remote node) side when it encounters a hit.
     * See [org.bitcoinj.core.BloomFilter.BloomUpdate] for a brief description of each mode. The purpose
     * of this flag is to reduce network round-tripping and avoid over-dirtying the filter for the most common
     * wallet configurations.
     */
    @JvmOverloads constructor(elements: Int, falsePositiveRate: Double, randomNonce: Long, updateFlag: BloomUpdate = BloomUpdate.UPDATE_P2PUBKEY_ONLY) {
        // The following formulas were stolen from Wikipedia's page on Bloom Filters (with the addition of min(..., MAX_...))
        //                        Size required for a given number of elements and false-positive rate
        var size = (-1 / pow(log(2.0), 2.0) * elements.toDouble() * log(falsePositiveRate)).toInt()
        size = max(1, min(size, MAX_FILTER_SIZE.toInt() * 8) / 8)
        data = ByteArray(size)
        // Optimal number of hash functions for a given filter size and element count.
        hashFuncs = (data!!.size * 8 / elements.toDouble() * log(2.0)).toInt().toLong()
        hashFuncs = max(1, min(hashFuncs, MAX_HASH_FUNCS.toLong()))
        this.nTweak = randomNonce
        this.nFlags = (0xff and updateFlag.ordinal).toByte()
    }

    /**
     * Returns the theoretical false positive rate of this filter if were to contain the given number of elements.
     */
    fun getFalsePositiveRate(elements: Int): Double {
        return pow(1 - pow(E, -1.0 * (hashFuncs * elements) / (data!!.size * 8)), hashFuncs.toDouble())
    }

    override fun toString(): String {
        return "Bloom Filter of size " + data!!.size + " with " + hashFuncs + " hash functions."
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        data = readByteArray()
        if (data!!.size > MAX_FILTER_SIZE)
            throw ProtocolException("Bloom filter out of size range.")
        hashFuncs = readUint32()
        if (hashFuncs > MAX_HASH_FUNCS)
            throw ProtocolException("Bloom filter hash function count out of range")
        nTweak = readUint32()
        nFlags = readBytes(1)[0]
        length = cursor - offset
    }

    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
     */
    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
        stream.write(VarInt(data!!.size.toLong()).encode())
        stream.write(data!!)
        Utils.uint32ToByteStreamLE(hashFuncs, stream)
        Utils.uint32ToByteStreamLE(nTweak, stream)
        stream.write(nFlags.toInt())
    }

    /**
     * Returns true if the given object matches the filter either because it was inserted, or because we have a
     * false-positive.
     */
    @Synchronized operator fun contains(`object`: ByteArray?): Boolean {
        for (i in 0 until hashFuncs) {
            if (!Utils.checkBitLE(data!!, murmurHash3(data, nTweak, i, `object`!!)))
                return false
        }
        return true
    }

    /** Insert the given arbitrary data into the filter  */
    @Synchronized
    fun insert(`object`: ByteArray) {
        for (i in 0 until hashFuncs)
            Utils.setBitLE(data!!, murmurHash3(data, nTweak, i, `object`))
    }

    /** Inserts the given key and equivalent hashed form (for the address).  */
    @Synchronized
    fun insert(key: ECKey) {
        insert(key.pubKey)
        insert(key.pubKeyHash)
    }

    /**
     * Sets this filter to match all objects. A Bloom filter which matches everything may seem pointless, however,
     * it is useful in order to reduce steady state bandwidth usage when you want full blocks. Instead of receiving
     * all transaction data twice, you will receive the vast majority of all transactions just once, at broadcast time.
     * Solved blocks will then be send just as Merkle trees of tx hashes, meaning a constant 32 bytes of data for each
     * transaction instead of 100-300 bytes as per usual.
     */
    @Synchronized
    fun setMatchAll() {
        data = byteArrayOf(0xff.toByte())
    }

    /**
     * Copies filter into this. Filter must have the same size, hash function count and nTweak or an
     * IllegalArgumentException will be thrown.
     */
    @Synchronized
    fun merge(filter: BloomFilter) {
        if (!this.matchesAll() && !filter.matchesAll()) {
            checkArgument(filter.data!!.size == this.data!!.size &&
                    filter.hashFuncs == this.hashFuncs &&
                    filter.nTweak == this.nTweak)
            for (i in data!!.indices)
                this.data[i] = this.data[i] or filter.data!![i]
        } else {
            this.data = byteArrayOf(0xff.toByte())
        }
    }

    /**
     * Returns true if this filter will match anything. See [org.bitcoinj.core.BloomFilter.setMatchAll]
     * for when this can be a useful thing to do.
     */
    @Synchronized
    fun matchesAll(): Boolean {
        for (b in data!!)
            if (b != 0xff.toByte())
                return false
        return true
    }

    /**
     * Creates a new FilteredBlock from the given Block, using this filter to select transactions. Matches can cause the
     * filter to be updated with the matched element, this ensures that when a filter is applied to a block, spends of
     * matched transactions are also matched. However it means this filter can be mutated by the operation. The returned
     * filtered block already has the matched transactions associated with it.
     */
    @Synchronized
    fun applyAndUpdate(block: Block): FilteredBlock {
        val txns = block.getTransactions()
        val txHashes = ArrayList<Sha256Hash>(txns!!.size)
        val matched = Lists.newArrayList<Transaction>()
        val bits = ByteArray(Math.ceil(txns.size / 8.0).toInt())
        for (i in txns.indices) {
            val tx = txns[i]
            txHashes.add(tx.hash)
            if (applyAndUpdate(tx)) {
                Utils.setBitLE(bits, i)
                matched.add(tx)
            }
        }
        val pmt = PartialMerkleTree.buildFromLeaves(block.params, bits, txHashes)
        val filteredBlock = FilteredBlock(block.params, block.cloneAsHeader(), pmt)
        for (transaction in matched)
            filteredBlock.provideTransaction(transaction)
        return filteredBlock
    }

    @Synchronized
    fun applyAndUpdate(tx: Transaction): Boolean {
        if (contains(tx.hash.bytes))
            return true
        var found = false
        val flag = updateFlag
        for (output in tx.outputs) {
            val script = output.scriptPubKey
            for (chunk in script.chunks) {
                if (!chunk.isPushData)
                    continue
                if (contains(chunk.data)) {
                    val isSendingToPubKeys = script.isSentToRawPubKey || script.isSentToMultiSig
                    if (flag == BloomUpdate.UPDATE_ALL || flag == BloomUpdate.UPDATE_P2PUBKEY_ONLY && isSendingToPubKeys)
                        insert(output.outPointFor.unsafeBitcoinSerialize())
                    found = true
                }
            }
        }
        if (found) return true
        for (input in tx.inputs) {
            if (contains(input.outpoint!!.unsafeBitcoinSerialize())) {
                return true
            }
            for (chunk in input.scriptSig.chunks) {
                if (chunk.isPushData && contains(chunk.data))
                    return true
            }
        }
        return false
    }

    @Synchronized override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as BloomFilter?
        return hashFuncs == other!!.hashFuncs && nTweak == other.nTweak && Arrays.equals(data, other.data)
    }

    @Synchronized override fun hashCode(): Int {
        return Objects.hashCode(hashFuncs, nTweak, Arrays.hashCode(data))
    }

    companion object {

        // Same value as Bitcoin Core
        // A filter of 20,000 items and a false positive rate of 0.1% or one of 10,000 items and 0.0001% is just under 36,000 bytes
        private val MAX_FILTER_SIZE: Long = 36000
        // There is little reason to ever have more hash functions than 50 given a limit of 36,000 bytes
        private val MAX_HASH_FUNCS = 50

        private fun rotateLeft32(x: Int, r: Int): Int {
            return x shl r or x.ushr(32 - r)
        }

        /**
         * Applies the MurmurHash3 (x86_32) algorithm to the given data.
         * See this [C++ code for the original.](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp)
         */
        fun murmurHash3(data: ByteArray, nTweak: Long, hashNum: Int, `object`: ByteArray): Int {
            var h1 = (hashNum * 0xFBA4C795L + nTweak).toInt()
            val c1 = -0x3361d2af
            val c2 = 0x1b873593

            val numBlocks = `object`.size / 4 * 4
            // body
            var i = 0
            while (i < numBlocks) {
                var k1 = `object`[i] and 0xFF or
                        (`object`[i + 1] and 0xFF shl 8) or
                        (`object`[i + 2] and 0xFF shl 16) or
                        (`object`[i + 3] and 0xFF shl 24)

                k1 *= c1
                k1 = rotateLeft32(k1, 15)
                k1 *= c2

                h1 = h1 xor k1
                h1 = rotateLeft32(h1, 13)
                h1 = h1 * 5 + -0x19ab949c
                i += 4
            }

            var k1 = 0
            when (`object`.size and 3) {
                3 -> {
                    k1 = k1 xor (`object`[numBlocks + 2] and 0xff shl 16)
                    k1 = k1 xor (`object`[numBlocks + 1] and 0xff shl 8)
                    k1 = k1 xor (`object`[numBlocks] and 0xff)
                    k1 *= c1
                    k1 = rotateLeft32(k1, 15)
                    k1 *= c2
                    h1 = h1 xor k1
                }
            // Fall through.
                2 -> {
                    k1 = k1 xor (`object`[numBlocks + 1] and 0xff shl 8)
                    k1 = k1 xor (`object`[numBlocks] and 0xff)
                    k1 *= c1
                    k1 = rotateLeft32(k1, 15)
                    k1 *= c2
                    h1 = h1 xor k1
                }
            // Fall through.
                1 -> {
                    k1 = k1 xor (`object`[numBlocks] and 0xff)
                    k1 *= c1
                    k1 = rotateLeft32(k1, 15)
                    k1 *= c2
                    h1 = h1 xor k1
                }
            // Fall through.
                else -> {
                }
            }// Do nothing.

            // finalization
            h1 = h1 xor `object`.size
            h1 = h1 xor h1.ushr(16)
            h1 *= -0x7a143595
            h1 = h1 xor h1.ushr(13)
            h1 *= -0x3d4d51cb
            h1 = h1 xor h1.ushr(16)

            return ((h1 and 0xFFFFFFFFL) % (data.size * 8)).toInt()
        }
    }
}
/**
 * Constructs a filter with the given parameters which is updated on pay2pubkey outputs only.
 */
