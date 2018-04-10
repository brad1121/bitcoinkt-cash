/*
 * Copyright 2012 The Bitcoin Developers
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

import java.io.IOException
import java.io.OutputStream
import java.util.ArrayList
import java.util.Arrays

import org.bitcoinj.core.Utils.*
import com.google.common.base.Objects

/**
 *
 * A data structure that contains proofs of block inclusion for one or more transactions, in an efficient manner.
 *
 *
 * The encoding works as follows: we traverse the tree in depth-first order, storing a bit for each traversed node,
 * signifying whether the node is the parent of at least one matched leaf txid (or a matched txid itself). In case we
 * are at the leaf level, or this bit is 0, its merkle node hash is stored, and its children are not explored further.
 * Otherwise, no hash is stored, but we recurse into both (or the only) child branch. During decoding, the same
 * depth-first traversal is performed, consuming bits and hashes as they were written during encoding.
 *
 *
 * The serialization is fixed and provides a hard guarantee about the encoded size,
 * <tt>SIZE &lt;= 10 + ceil(32.25*N)</tt> where N represents the number of leaf nodes of the partial tree. N itself
 * is bounded by:
 *
 *
 *
 * N &lt;= total_transactions<br></br>
 * N &lt;= 1 + matched_transactions*tree_height
 *
 *
 *
 * <pre>The serialization format:
 * - uint32     total_transactions (4 bytes)
 * - varint     number of hashes   (1-3 bytes)
 * - uint256[]  hashes in depth-first order (&lt;= 32*N bytes)
 * - varint     number of bytes of flag bits (1-3 bytes)
 * - byte[]     flag bits, packed per 8 in a byte, least significant bit first (&lt;= 2*N-1 bits)
 * The size constraints follow from this.</pre>
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class PartialMerkleTree : Message {
    // the total number of transactions in the block
    var transactionCount: Int = 0
        private set

    // node-is-parent-of-matched-txid bits
    private var matchedChildBits: ByteArray? = null

    // txids and internal hashes
    private var hashes: MutableList<Sha256Hash>? = null

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray, offset: Int) : super(params, payloadBytes, offset) {
    }

    /**
     * Constructs a new PMT with the given bit set (little endian) and the raw list of hashes including internal hashes,
     * taking ownership of the list.
     */
    constructor(params: NetworkParameters, bits: ByteArray, hashes: MutableList<Sha256Hash>, origTxCount: Int) : super(params) {
        this.matchedChildBits = bits
        this.hashes = hashes
        this.transactionCount = origTxCount
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(stream: OutputStream) {
        uint32ToByteStreamLE(transactionCount.toLong(), stream)

        stream.write(VarInt(hashes!!.size.toLong()).encode())
        for (hash in hashes!!)
            stream.write(hash.reversedBytes)

        stream.write(VarInt(matchedChildBits!!.size.toLong()).encode())
        stream.write(matchedChildBits!!)
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        transactionCount = readUint32().toInt()

        val nHashes = readVarInt().toInt()
        hashes = ArrayList(nHashes)
        for (i in 0 until nHashes)
            hashes!!.add(readHash())

        val nFlagBytes = readVarInt().toInt()
        matchedChildBits = readBytes(nFlagBytes)

        length = cursor - offset
    }

    private class ValuesUsed {
        var bitsUsed = 0
        var hashesUsed = 0
    }

    // recursive function that traverses tree nodes, consuming the bits and hashes produced by TraverseAndBuild.
    // it returns the hash of the respective node.
    @Throws(VerificationException::class)
    private fun recursiveExtractHashes(height: Int, pos: Int, used: ValuesUsed, matchedHashes: MutableList<Sha256Hash>): Sha256Hash {
        if (used.bitsUsed >= matchedChildBits!!.size * 8) {
            // overflowed the bits array - failure
            throw VerificationException("PartialMerkleTree overflowed its bits array")
        }
        val parentOfMatch = checkBitLE(matchedChildBits!!, used.bitsUsed++)
        if (height == 0 || !parentOfMatch) {
            // if at height 0, or nothing interesting below, use stored hash and do not descend
            if (used.hashesUsed >= hashes!!.size) {
                // overflowed the hash array - failure
                throw VerificationException("PartialMerkleTree overflowed its hash array")
            }
            val hash = hashes!![used.hashesUsed++]
            if (height == 0 && parentOfMatch)
            // in case of height 0, we have a matched txid
                matchedHashes.add(hash)
            return hash
        } else {
            // otherwise, descend into the subtrees to extract matched txids and hashes
            val left = recursiveExtractHashes(height - 1, pos * 2, used, matchedHashes).bytes
            val right: ByteArray
            if (pos * 2 + 1 < getTreeWidth(transactionCount, height - 1)) {
                right = recursiveExtractHashes(height - 1, pos * 2 + 1, used, matchedHashes).bytes
                if (Arrays.equals(right, left))
                    throw VerificationException("Invalid merkle tree with duplicated left/right branches")
            } else {
                right = left
            }
            // and combine them before returning
            return combineLeftRight(left, right)
        }
    }

    /**
     * Extracts tx hashes that are in this merkle tree
     * and returns the merkle root of this tree.
     *
     * The returned root should be checked against the
     * merkle root contained in the block header for security.
     *
     * @param matchedHashesOut A list which will contain the matched txn (will be cleared).
     * @return the merkle root of this merkle tree
     * @throws ProtocolException if this partial merkle tree is invalid
     */
    @Throws(VerificationException::class)
    fun getTxnHashAndMerkleRoot(matchedHashesOut: MutableList<Sha256Hash>): Sha256Hash {
        matchedHashesOut.clear()

        // An empty set will not work
        if (transactionCount == 0)
            throw VerificationException("Got a CPartialMerkleTree with 0 transactions")
        // check for excessively high numbers of transactions
        if (transactionCount > Block.MAX_BLOCK_SIZE / 60)
        // 60 is the lower bound for the size of a serialized CTransaction
            throw VerificationException("Got a CPartialMerkleTree with more transactions than is possible")
        // there can never be more hashes provided than one for every txid
        if (hashes!!.size > transactionCount)
            throw VerificationException("Got a CPartialMerkleTree with more hashes than transactions")
        // there must be at least one bit per node in the partial tree, and at least one node per hash
        if (matchedChildBits!!.size * 8 < hashes!!.size)
            throw VerificationException("Got a CPartialMerkleTree with fewer matched bits than hashes")
        // calculate height of tree
        var height = 0
        while (getTreeWidth(transactionCount, height) > 1)
            height++
        // traverse the partial tree
        val used = ValuesUsed()
        val merkleRoot = recursiveExtractHashes(height, 0, used, matchedHashesOut)
        // verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
        if ((used.bitsUsed + 7) / 8 != matchedChildBits!!.size ||
                // verify that all hashes were consumed
                used.hashesUsed != hashes!!.size)
            throw VerificationException("Got a CPartialMerkleTree that didn't need all the data it provided")

        return merkleRoot
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as PartialMerkleTree?
        return (transactionCount == other!!.transactionCount && hashes == other.hashes
                && Arrays.equals(matchedChildBits, other.matchedChildBits))
    }

    override fun hashCode(): Int {
        return Objects.hashCode(transactionCount, hashes, Arrays.hashCode(matchedChildBits))
    }

    override fun toString(): String {
        return "PartialMerkleTree{" +
                "transactionCount=" + transactionCount +
                ", matchedChildBits=" + Arrays.toString(matchedChildBits) +
                ", hashes=" + hashes +
                '}'
    }

    companion object {

        /**
         * Calculates a PMT given the list of leaf hashes and which leaves need to be included. The relevant interior hashes
         * are calculated and a new PMT returned.
         */
        fun buildFromLeaves(params: NetworkParameters, includeBits: ByteArray, allLeafHashes: List<Sha256Hash>): PartialMerkleTree {
            // Calculate height of the tree.
            var height = 0
            while (getTreeWidth(allLeafHashes.size, height) > 1)
                height++
            val bitList = ArrayList<Boolean>()
            val hashes = ArrayList<Sha256Hash>()
            traverseAndBuild(height, 0, allLeafHashes, includeBits, bitList, hashes)
            val bits = ByteArray(Math.ceil(bitList.size / 8.0).toInt())
            for (i in bitList.indices)
                if (bitList[i])
                    Utils.setBitLE(bits, i)
            return PartialMerkleTree(params, bits, hashes, allLeafHashes.size)
        }

        // Based on CPartialMerkleTree::TraverseAndBuild in Bitcoin Core.
        private fun traverseAndBuild(height: Int, pos: Int, allLeafHashes: List<Sha256Hash>, includeBits: ByteArray,
                                     matchedChildBits: MutableList<Boolean>, resultHashes: MutableList<Sha256Hash>) {
            var parentOfMatch = false
            // Is this node a parent of at least one matched hash?
            run {
                var p = pos shl height
                while (p < pos + 1 shl height && p < allLeafHashes.size) {
                    if (Utils.checkBitLE(includeBits, p)) {
                        parentOfMatch = true
                        break
                    }
                    p++
                }
            }
            // Store as a flag bit.
            matchedChildBits.add(parentOfMatch)
            if (height == 0 || !parentOfMatch) {
                // If at height 0, or nothing interesting below, store hash and stop.
                resultHashes.add(calcHash(height, pos, allLeafHashes))
            } else {
                // Otherwise descend into the subtrees.
                val h = height - 1
                val p = pos * 2
                traverseAndBuild(h, p, allLeafHashes, includeBits, matchedChildBits, resultHashes)
                if (p + 1 < getTreeWidth(allLeafHashes.size, h))
                    traverseAndBuild(h, p + 1, allLeafHashes, includeBits, matchedChildBits, resultHashes)
            }
        }

        private fun calcHash(height: Int, pos: Int, hashes: List<Sha256Hash>): Sha256Hash {
            if (height == 0) {
                // Hash at height 0 is just the regular tx hash itself.
                return hashes[pos]
            }
            val h = height - 1
            val p = pos * 2
            val left = calcHash(h, p, hashes)
            // Calculate right hash if not beyond the end of the array - copy left hash otherwise.
            val right: Sha256Hash
            if (p + 1 < getTreeWidth(hashes.size, h)) {
                right = calcHash(h, p + 1, hashes)
            } else {
                right = left
            }
            return combineLeftRight(left.bytes, right.bytes)
        }

        // helper function to efficiently calculate the number of nodes at given height in the merkle tree
        private fun getTreeWidth(transactionCount: Int, height: Int): Int {
            return transactionCount + (1 shl height) - 1 shr height
        }

        private fun combineLeftRight(left: ByteArray, right: ByteArray): Sha256Hash {
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(
                    reverseBytes(left), 0, 32,
                    reverseBytes(right), 0, 32))
        }
    }
}
