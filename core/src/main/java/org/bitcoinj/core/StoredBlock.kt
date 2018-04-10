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

import org.bitcoinj.store.BlockStore
import org.bitcoinj.store.BlockStoreException
import com.google.common.base.Objects

import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.Locale

import com.google.common.base.Preconditions.checkState

/**
 * Wraps a [Block] object with extra data that can be derived from the block chain but is slow or inconvenient to
 * calculate. By storing it alongside the block header we reduce the amount of work required significantly.
 * Recalculation is slow because the fields are cumulative - to find the chainWork you have to iterate over every
 * block in the chain back to the genesis block, which involves lots of seeking/loading etc. So we just keep a
 * running total: it's a disk space vs cpu/io tradeoff.
 *
 *
 *
 * StoredBlocks are put inside a [BlockStore] which saves them to memory or disk.
 */
class StoredBlock(
        /**
         * The block header this object wraps. The referenced block object must not have any transactions in it.
         */
        val header: Block,
        /**
         * The total sum of work done in this block, and all the blocks below it in the chain. Work is a measure of how
         * many tries are needed to solve a block. If the target is set to cover 10% of the total hash value space,
         * then the work represented by a block is 10.
         */
        val chainWork: BigInteger,
        /**
         * Position in the chain for this block. The genesis block has a height of zero.
         */
        val height: Int) {

    /** Returns true if this objects chainWork is higher than the others.  */
    fun moreWorkThan(other: StoredBlock): Boolean {
        return chainWork.compareTo(other.chainWork) > 0
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as StoredBlock?
        return header == other!!.header && chainWork == other.chainWork && height == other.height
    }

    override fun hashCode(): Int {
        return Objects.hashCode(header, chainWork, height)
    }

    /**
     * Creates a new StoredBlock, calculating the additional fields by adding to the values in this block.
     */
    @Throws(VerificationException::class)
    fun build(block: Block): StoredBlock {
        // Stored blocks track total work done in this chain, because the canonical chain is the one that represents
        // the largest amount of work done not the tallest.
        val chainWork = this.chainWork.add(block.work)
        val height = this.height + 1
        return StoredBlock(block, chainWork, height)
    }

    /**
     * Given a block store, looks up the previous block in this chain. Convenience method for doing
     * <tt>store.get(this.getHeader().getPrevBlockHash())</tt>.
     *
     * @return the previous block in the chain or null if it was not found in the store.
     */
    @Throws(BlockStoreException::class)
    fun getPrev(store: BlockStore): StoredBlock {
        return store.get(header.prevBlockHash)
    }

    /** Serializes the stored block to a custom packed format. Used by [CheckpointManager].  */
    fun serializeCompact(buffer: ByteBuffer) {
        val chainWorkBytes = chainWork.toByteArray()
        checkState(chainWorkBytes.size <= CHAIN_WORK_BYTES, "Ran out of space to store chain work!")
        if (chainWorkBytes.size < CHAIN_WORK_BYTES) {
            // Pad to the right size.
            buffer.put(EMPTY_BYTES, 0, CHAIN_WORK_BYTES - chainWorkBytes.size)
        }
        buffer.put(chainWorkBytes)
        buffer.putInt(height)
        // Using unsafeBitcoinSerialize here can give us direct access to the same bytes we read off the wire,
        // avoiding serialization round-trips.
        val bytes = header.unsafeBitcoinSerialize()
        buffer.put(bytes, 0, Block.HEADER_SIZE)  // Trim the trailing 00 byte (zero transactions).
    }

    override fun toString(): String {
        return String.format(Locale.US, "Block %s at height %d: %s",
                header.hashAsString, height, header.toString())
    }

    companion object {

        // A BigInteger representing the total amount of work done so far on this chain. As of May 2011 it takes 8
        // bytes to represent this field, so 12 bytes should be plenty for now.
        val CHAIN_WORK_BYTES = 12
        val EMPTY_BYTES = ByteArray(CHAIN_WORK_BYTES)
        val COMPACT_SERIALIZED_SIZE = Block.HEADER_SIZE + CHAIN_WORK_BYTES + 4  // for height

        /** De-serializes the stored block from a custom packed format. Used by [CheckpointManager].  */
        @Throws(ProtocolException::class)
        fun deserializeCompact(params: NetworkParameters, buffer: ByteBuffer): StoredBlock {
            val chainWorkBytes = ByteArray(StoredBlock.CHAIN_WORK_BYTES)
            buffer.get(chainWorkBytes)
            val chainWork = BigInteger(1, chainWorkBytes)
            val height = buffer.int  // +4 bytes
            val header = ByteArray(Block.HEADER_SIZE + 1)    // Extra byte for the 00 transactions length.
            buffer.get(header, 0, Block.HEADER_SIZE)
            return StoredBlock(params.getDefaultSerializer().makeBlock(header), chainWork, height)
        }
    }
}
