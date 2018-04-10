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

import com.google.common.base.Objects
import java.io.IOException
import java.io.OutputStream
import java.util.*

/**
 *
 * A FilteredBlock is used to relay a block with its transactions filtered using a [BloomFilter]. It consists
 * of the block header and a [PartialMerkleTree] which contains the transactions which matched the filter.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class FilteredBlock : Message {
    private var header: Block? = null

    /** Returns the [PartialMerkleTree] object that provides the mathematical proof of transaction inclusion in the block.  */
    var partialMerkleTree: PartialMerkleTree? = null
        private set
    private var cachedTransactionHashes: List<Sha256Hash>? = null

    // A set of transactions whose hashes are a subset of getTransactionHashes()
    // These were relayed as a part of the filteredblock getdata, ie likely weren't previously received as loose transactions
    private val associatedTransactions = HashMap<Sha256Hash, Transaction>()

    /**
     * Gets a list of leaf hashes which are contained in the partial merkle tree in this filtered block
     *
     * @throws ProtocolException If the partial merkle block is invalid or the merkle root of the partial merkle block doesnt match the block header
     */
    val transactionHashes: List<Sha256Hash>
        @Throws(VerificationException::class)
        get() {
            if (cachedTransactionHashes != null)
                return Collections.unmodifiableList(cachedTransactionHashes!!)
            val hashesMatched = LinkedList<Sha256Hash>()
            if (header!!.merkleRoot == partialMerkleTree!!.getTxnHashAndMerkleRoot(hashesMatched)) {
                cachedTransactionHashes = hashesMatched
                return Collections.unmodifiableList(cachedTransactionHashes!!)
            } else
                throw VerificationException("Merkle root of block header does not match merkle root of partial merkle tree.")
        }

    /**
     * Gets a copy of the block header
     */
    val blockHeader: Block
        get() = header!!.cloneAsHeader()

    /** Gets the hash of the block represented in this Filtered Block  */
    override val hash: Sha256Hash
        get() = header!!.hash

    /** Number of transactions in this block, before it was filtered  */
    val transactionCount: Int
        get() = partialMerkleTree!!.transactionCount

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray) : super(params, payloadBytes, 0) {
    }

    constructor(params: NetworkParameters, header: Block, pmt: PartialMerkleTree) : super(params) {
        this.header = header
        this.partialMerkleTree = pmt
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(stream: OutputStream) {
        if (header!!.transactions == null)
            header!!.bitcoinSerializeToStream(stream)
        else
            header!!.cloneAsHeader().bitcoinSerializeToStream(stream)
        partialMerkleTree!!.bitcoinSerializeToStream(stream)
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        val headerBytes = ByteArray(Block.HEADER_SIZE)
        System.arraycopy(payload!!, 0, headerBytes, 0, Block.HEADER_SIZE)
        header = params!!.getDefaultSerializer().makeBlock(headerBytes)

        partialMerkleTree = PartialMerkleTree(params, payload, Block.HEADER_SIZE)

        length = Block.HEADER_SIZE + partialMerkleTree!!.messageSize
    }

    /**
     * Provide this FilteredBlock with a transaction which is in its Merkle tree.
     * @return false if the tx is not relevant to this FilteredBlock
     */
    @Throws(VerificationException::class)
    fun provideTransaction(tx: Transaction): Boolean {
        val hash = tx.hash
        if (transactionHashes.contains(hash)) {
            associatedTransactions.put(hash, tx)
            return true
        }
        return false
    }

    /** Gets the set of transactions which were provided using provideTransaction() which match in getTransactionHashes()  */
    fun getAssociatedTransactions(): Map<Sha256Hash, Transaction> {
        return Collections.unmodifiableMap(associatedTransactions)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as FilteredBlock?
        return (associatedTransactions == other!!.associatedTransactions
                && header == other.header && partialMerkleTree == other.partialMerkleTree)
    }

    override fun hashCode(): Int {
        return Objects.hashCode(associatedTransactions, header, partialMerkleTree)
    }

    override fun toString(): String {
        return "FilteredBlock{merkleTree=$partialMerkleTree, header=$header}"
    }
}
