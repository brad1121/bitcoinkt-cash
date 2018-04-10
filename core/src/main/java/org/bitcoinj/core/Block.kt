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

import com.google.common.annotations.*
import com.google.common.base.*
import com.google.common.collect.*
import org.bitcoinj.script.*
import org.slf4j.*

import javax.annotation.*
import java.io.*
import java.math.*
import java.util.*

import org.bitcoinj.core.Coin.*
import org.bitcoinj.core.Sha256Hash.*

/**
 *
 * A block is a group of transactions, and is one of the fundamental data structures of the Bitcoin system.
 * It records a set of [Transaction]s together with some data that links it into a place in the global block
 * chain, and proves that a difficult calculation was done over its contents. See
 * [the Bitcoin technical paper](http://www.bitcoin.org/bitcoin.pdf) for
 * more detail on blocks.
 *
 *
 *
 *
 * To get a block, you can either build one from the raw bytes you can get from another implementation, or request one
 * specifically using [Peer.getBlock], or grab one from a downloaded [BlockChain].
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class Block : Message {

    // Fields defined as part of the protocol format.
    /** Returns the version of the block data structure as defined by the Bitcoin protocol.  */
    var version: Long = 0
        private set
    private var prevBlockHash: Sha256Hash? = null
    private var merkleRoot: Sha256Hash? = null
    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node. This
     * is measured in seconds since the UNIX epoch (midnight Jan 1st 1970).
     */
    var timeSeconds: Long = 0
        private set
    private var difficultyTarget: Long = 0 // "nBits"
    private var nonce: Long = 0

    // TODO: Get rid of all the direct accesses to this field. It's a long-since unnecessary holdover from the Dalvik days.
    /** If null, it means this object holds only the headers.  */
    internal var transactions: MutableList<Transaction>? = null

    /** Stores the hash of the block. If null, getHash() will recalculate it.  */
    override var hash: Sha256Hash? = null
    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
        get(): Sha256Hash? {
            if (hash == null)
                hash = calculateHash()
            return hash as Sha256Hash
        }
    @get:VisibleForTesting
    private var isHeaderBytesValid: Boolean = false

    @get:VisibleForTesting
    private var isTransactionBytesValid: Boolean = false


    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    var optimalEncodingMessageSize: Int = 0
        get(): Int {
            if (optimalEncodingMessageSize != 0)
                return optimalEncodingMessageSize
            optimalEncodingMessageSize = bitcoinSerialize().size
            return optimalEncodingMessageSize
        }
    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the mainnet chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    val hashAsString: String
        get() = hash.toString()

    /**
     * Returns the work represented by this block.
     *
     *
     *
     * Work is defined as the number of tries needed to solve a block in the
     * average case. Consider a difficulty target that covers 5% of all possible
     * hash values. Then the work of the block will be 20. As the target gets
     * lower, the amount of work goes up.
     */
    val work: BigInteger
        @Throws(VerificationException::class)
        get() {
            val target = difficultyTargetAsInteger
            return LARGEST_HASH.divide(target.add(BigInteger.ONE))
        }

    /**
     * Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash. Inside a block the
     * target is represented using a compact form. If this form decodes to a value that is out of bounds, an exception
     * is thrown.
     */
    val difficultyTargetAsInteger: BigInteger
        @Throws(VerificationException::class)
        get() {
            val target = Utils.decodeCompactBits(difficultyTarget)
            if (target.signum() <= 0 || target.compareTo(params!!.maxTarget!!) > 0)
                throw VerificationException("Difficulty target is bad: " + target.toString())
            return target
        }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node.
     */
    val time: Date
        get() = Date(timeSeconds * 1000)

    /**
     * Returns whether this block conforms to
     * [BIP34: Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki).
     */
    val isBIP34: Boolean
        get() = version >= BLOCK_VERSION_BIP34

    /**
     * Returns whether this block conforms to
     * [BIP66: Strict DER signatures](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).
     */
    val isBIP66: Boolean
        get() = version >= BLOCK_VERSION_BIP66

    /**
     * Returns whether this block conforms to
     * [BIP65: OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki).
     */
    val isBIP65: Boolean
        get() = version >= BLOCK_VERSION_BIP65

    /**
     * Flags used to control which elements of block validation are done on
     * received blocks.
     */
    enum class VerifyFlag {
        /** Check that block height is in coinbase transaction (BIP 34).  */
        HEIGHT_IN_COINBASE
    }

    /** Special case constructor, used for the genesis node, cloneAsHeader and unit tests.  */
    internal constructor(params: NetworkParameters, setVersion: Long) : super(params) {
        // Set up a few basic things. We are not complete after this though.
        version = setVersion
        difficultyTarget = 0x1d07fff8L
        timeSeconds = System.currentTimeMillis() / 1000
        prevBlockHash = Sha256Hash.ZERO_HASH

        length = HEADER_SIZE
    }

    /**
     * Constructs a block object from the Bitcoin wire format.
     */
    @Deprecated("Use {@link BitcoinSerializer#makeBlock(byte[])} instead.")
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray) : super(params, payloadBytes, 0, params.defaultSerializer, payloadBytes.size) {
    }

    /**
     * Construct a block object from the Bitcoin wire format.
     * @param params NetworkParameters object.
     * @param payloadBytes the payload to extract the block from.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray, serializer: MessageSerializer, length: Int) : super(params, payloadBytes, 0, serializer, length) {
    }

    /**
     * Construct a block object from the Bitcoin wire format.
     * @param params NetworkParameters object.
     * @param payloadBytes the payload to extract the block from.
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray, offset: Int, serializer: MessageSerializer, length: Int) : super(params, payloadBytes, offset, serializer, length) {
    }

    /**
     * Construct a block object from the Bitcoin wire format. Used in the case of a block
     * contained within another message (i.e. for AuxPoW header).
     *
     * @param params NetworkParameters object.
     * @param payloadBytes Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param parent The message element which contains this block, maybe null for no parent.
     * @param serializer the serializer to use for this block.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray, offset: Int, parent: Message?, serializer: MessageSerializer, length: Int) : super(params, payloadBytes, offset, serializer, length) {
    }// TODO: Keep the parent

    /**
     * Construct a block initialized with all the given fields.
     * @param params Which network the block is for.
     * @param version This should usually be set to 1 or 2, depending on if the height is in the coinbase input.
     * @param prevBlockHash Reference to previous block in the chain or [Sha256Hash.ZERO_HASH] if genesis.
     * @param merkleRoot The root of the merkle tree formed by the transactions.
     * @param time UNIX time when the block was mined.
     * @param difficultyTarget Number which this block hashes lower than.
     * @param nonce Arbitrary number to make the block hash lower than the target.
     * @param transactions List of transactions including the coinbase.
     */
    constructor(params: NetworkParameters, version: Long, prevBlockHash: Sha256Hash, merkleRoot: Sha256Hash, time: Long,
                difficultyTarget: Long, nonce: Long, transactions: List<Transaction>) : super(params) {
        this.version = version
        this.prevBlockHash = prevBlockHash
        this.merkleRoot = merkleRoot
        this.timeSeconds = time
        this.difficultyTarget = difficultyTarget
        this.nonce = nonce
        this.transactions = LinkedList()
        this.transactions!!.addAll(transactions)
    }


    /**
     *
     * A utility method that calculates how much new Bitcoin would be created by the block at the given height.
     * The inflation of Bitcoin is predictable and drops roughly every 4 years (210,000 blocks). At the dawn of
     * the system it was 50 coins per block, in late 2012 it went to 25 coins per block, and so on. The size of
     * a coinbase transaction is inflation plus fees.
     *
     *
     * The half-life is controlled by [org.bitcoinj.core.NetworkParameters.getSubsidyDecreaseBlockCount].
     *
     */
    fun getBlockInflation(height: Int): Coin {
        return Coin.FIFTY_COINS.shiftRight(height / params!!.subsidyDecreaseBlockCount)
    }

    /**
     * Parse transactions from the block.
     *
     * @param transactionsOffset Offset of the transactions within the block.
     * Useful for non-Bitcoin chains where the block header may not be a fixed
     * size.
     */
    @Throws(ProtocolException::class)
    protected fun parseTransactions(transactionsOffset: Int) {
        cursor = transactionsOffset
        optimalEncodingMessageSize = HEADER_SIZE
        if (payload!!.size == cursor) {
            // This message is just a header, it has no transactions.
            isTransactionBytesValid = false
            return
        }

        val numTransactions = readVarInt().toInt()
        optimalEncodingMessageSize += VarInt.sizeOf(numTransactions.toLong())
        transactions = ArrayList(numTransactions)
        for (i in 0 until numTransactions) {
            val tx = Transaction(params, payload, cursor, this, serializer!!, Message.UNKNOWN_LENGTH)
            // Label the transaction as coming from the P2P network, so code that cares where we first saw it knows.
            tx.getConfidence().source = TransactionConfidence.Source.NETWORK
            transactions!!.add(tx)
            cursor += tx.messageSize
            optimalEncodingMessageSize += tx.getOptimalEncodingMessageSize()
        }
        isTransactionBytesValid = serializer!!.isParseRetainMode
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        // header
        cursor = offset
        version = readUint32()
        prevBlockHash = readHash()
        merkleRoot = readHash()
        timeSeconds = readUint32()
        difficultyTarget = readUint32()
        nonce = readUint32()
        hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, cursor - offset))
        isHeaderBytesValid = serializer!!.isParseRetainMode

        // transactions
        parseTransactions(offset + HEADER_SIZE)
        length = cursor - offset
    }



    // default for testing
    @Throws(IOException::class)
    internal fun writeHeader(stream: OutputStream) {
        // try for cached write first
        if (isHeaderBytesValid && payload != null && payload!!.size >= offset + HEADER_SIZE) {
            stream.write(payload!!, offset, HEADER_SIZE)
            return
        }
        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream)
        stream.write(prevBlockHash!!.reversedBytes)
        stream.write(getMerkleRoot().reversedBytes)
        Utils.uint32ToByteStreamLE(timeSeconds, stream)
        Utils.uint32ToByteStreamLE(difficultyTarget, stream)
        Utils.uint32ToByteStreamLE(nonce, stream)
    }

    @Throws(IOException::class)
    private fun writeTransactions(stream: OutputStream) {
        // check for no transaction conditions first
        // must be a more efficient way to do this but I'm tired atm.
        if (transactions == null) {
            return
        }

        // confirmed we must have transactions either cached or as objects.
        if (isTransactionBytesValid && payload != null && payload!!.size >= offset + length) {
            stream.write(payload!!, offset + HEADER_SIZE, length - HEADER_SIZE)
            return
        }

        if (transactions != null) {
            stream.write(VarInt(transactions!!.size.toLong()).encode())
            for (tx in transactions!!) {
                tx.bitcoinSerialize(stream)
            }
        }
    }

    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     * @throws IOException
     */
    override fun bitcoinSerialize(): ByteArray {
        // we have completely cached byte array.
        if (isHeaderBytesValid && isTransactionBytesValid) {
            Preconditions.checkNotNull(payload, "Bytes should never be null if headerBytesValid && transactionBytesValid")
            if (length == payload!!.size) {
                return payload as ByteArray
            } else {
                // byte array is offset so copy out the correct range.
                val buf = ByteArray(length)
                System.arraycopy(payload!!, offset, buf, 0, length)
                return buf
            }
        }

        // At least one of the two cacheable components is invalid
        // so fall back to stream write since we can't be sure of the length.
        val stream = UnsafeByteArrayOutputStream(if (length == Message.UNKNOWN_LENGTH) HEADER_SIZE + guessTransactionsLength() else length)
        try {
            writeHeader(stream)
            writeTransactions(stream)
        } catch (e: IOException) {
            // Cannot happen, we are serializing to a memory stream.
        }

        return stream.toByteArray()
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(stream: OutputStream) {
        writeHeader(stream)
        // We may only have enough data to write the header.
        writeTransactions(stream)
    }

    /**
     * Provides a reasonable guess at the byte length of the transactions part of the block.
     * The returned value will be accurate in 99% of cases and in those cases where not will probably slightly
     * oversize.
     *
     * This is used to preallocate the underlying byte array for a ByteArrayOutputStream.  If the size is under the
     * real value the only penalty is resizing of the underlying byte array.
     */
    private fun guessTransactionsLength(): Int {
        if (isTransactionBytesValid)
            return payload!!.size - HEADER_SIZE
        if (transactions == null)
            return 0
        var len = VarInt.sizeOf(transactions!!.size.toLong())
        for (tx in transactions!!) {
            // 255 is just a guess at an average tx length
            len += if (tx.length == Message.UNKNOWN_LENGTH) 255 else tx.length
        }
        return len
    }

    public override fun unCache() {
        // Since we have alternate uncache methods to use internally this will only ever be called by a child
        // transaction so we only need to invalidate that part of the cache.
        unCacheTransactions()
    }

    private fun unCacheHeader() {
        isHeaderBytesValid = false
        if (!isTransactionBytesValid)
            payload = null
        hash = null
    }

    private fun unCacheTransactions() {
        isTransactionBytesValid = false
        if (!isHeaderBytesValid)
            payload = null
        // Current implementation has to uncache headers as well as any change to a tx will alter the merkle root. In
        // future we can go more granular and cache merkle root separately so rest of the header does not need to be
        // rewritten.
        unCacheHeader()
        // Clear merkleRoot last as it may end up being parsed during unCacheHeader().
        merkleRoot = null
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    private fun calculateHash(): Sha256Hash {
        try {
            val bos = UnsafeByteArrayOutputStream(HEADER_SIZE)
            writeHeader(bos)
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()))
        } catch (e: IOException) {
            throw RuntimeException(e) // Cannot happen.
        }

    }



    /** Returns a copy of the block, but without any transactions.  */
    fun cloneAsHeader(): Block {
        val block = Block(params!!, BLOCK_VERSION_GENESIS)
        copyBitcoinHeaderTo(block)
        return block
    }

    /** Copy the block without transactions into the provided empty block.  */
    protected fun copyBitcoinHeaderTo(block: Block) {
        block.nonce = nonce
        block.prevBlockHash = prevBlockHash
        block.merkleRoot = getMerkleRoot()
        block.version = version
        block.timeSeconds = timeSeconds
        block.difficultyTarget = difficultyTarget
        block.transactions = null
        block.hash = hash
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    override fun toString(): String {
        val s = StringBuilder()
        s.append(" block: \n")
        s.append("   hash: ").append(hashAsString).append('\n')
        s.append("   version: ").append(version)
        val bips = Joiner.on(", ").skipNulls().join(if (isBIP34) "BIP34" else null, if (isBIP66) "BIP66" else null,
                if (isBIP65) "BIP65" else null)
        if (!bips.isEmpty())
            s.append(" (").append(bips).append(')')
        s.append('\n')
        s.append("   previous block: ").append(getPrevBlockHash()).append("\n")
        s.append("   merkle root: ").append(getMerkleRoot()).append("\n")
        s.append("   time: ").append(timeSeconds).append(" (").append(Utils.dateTimeFormat(timeSeconds * 1000)).append(")\n")
        s.append("   difficulty target (nBits): ").append(difficultyTarget).append("\n")
        s.append("   nonce: ").append(nonce).append("\n")
        if (transactions != null && transactions!!.size > 0) {
            s.append("   with ").append(transactions!!.size).append(" transaction(s):\n")
            for (tx in transactions!!) {
                s.append(tx)
            }
        }
        return s.toString()
    }

    /**
     *
     * Finds a value of nonce that makes the blocks hash lower than the difficulty target. This is called mining, but
     * solve() is far too slow to do real mining with. It exists only for unit testing purposes.
     *
     *
     * This can loop forever if a solution cannot be found solely by incrementing nonce. It doesn't change
     * extraNonce.
     */
    fun solve() {
        while (true) {
            try {
                // Is our proof of work valid yet?
                if (checkProofOfWork(false))
                    return
                // No, so increment the nonce and try again.
                setNonce(getNonce() + 1)
            } catch (e: VerificationException) {
                throw RuntimeException(e) // Cannot happen.
            }

        }
    }

    /** Returns true if the hash of the block is OK (lower than difficulty target).  */
    @Throws(VerificationException::class)
    protected fun checkProofOfWork(throwException: Boolean): Boolean {
        // This part is key - it is what proves the block was as difficult to make as it claims
        // to be. Note however that in the context of this function, the block can claim to be
        // as difficult as it wants to be .... if somebody was able to take control of our network
        // connection and fork us onto a different chain, they could send us valid blocks with
        // ridiculously easy difficulty and this function would accept them.
        //
        // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
        // field is of the right value. This requires us to have the preceeding blocks.
        val target = difficultyTargetAsInteger

        val h = hash!!.toBigInteger()
        return if (h.compareTo(target) > 0) {
            // Proof of work check failed!
            if (throwException)
                throw VerificationException("Hash is higher than target: " + hashAsString + " vs "
                        + target.toString(16))
            else
                false
        } else true
    }

    @Throws(VerificationException::class)
    private fun checkTimestamp() {
        // Allow injection of a fake clock to allow unit testing.
        val currentTime = Utils.currentTimeSeconds()
        if (timeSeconds > currentTime + ALLOWED_TIME_DRIFT)
            throw VerificationException(String.format(Locale.US, "Block too far in future: %d vs %d", timeSeconds, currentTime + ALLOWED_TIME_DRIFT))
    }

    @Throws(VerificationException::class)
    private fun checkSigOps() {
        // Check there aren't too many signature verifications in the block. This is an anti-DoS measure, see the
        // comments for MAX_BLOCK_SIGOPS.
        var sigOps = 0
        for (tx in transactions!!) {
            sigOps += tx.sigOpCount
        }
        if (sigOps > MAX_BLOCK_SIGOPS)
            throw VerificationException("Block had too many Signature Operations")
    }

    @Throws(VerificationException::class)
    private fun checkMerkleRoot() {
        val calculatedRoot = calculateMerkleRoot()
        if (calculatedRoot != merkleRoot) {
            log.error("Merkle tree did not verify")
            throw VerificationException("Merkle hashes do not match: $calculatedRoot vs $merkleRoot")
        }
    }

    private fun calculateMerkleRoot(): Sha256Hash {
        val tree = buildMerkleTree()
        return Sha256Hash.wrap(tree[tree.size - 1])
    }

    private fun buildMerkleTree(): List<ByteArray> {
        // The Merkle root is based on a tree of hashes calculated from the transactions:
        //
        //     root
        //      / \
        //   A      B
        //  / \    / \
        // t1 t2 t3 t4
        //
        // The tree is represented as a list: t1,t2,t3,t4,A,B,root where each
        // entry is a hash.
        //
        // The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
        // The interior nodes are hashes of the concenation of the two child hashes.
        //
        // This structure allows the creation of proof that a transaction was included into a block without having to
        // provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
        // in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
        // derive the root, which can be checked against the block header. These proofs aren't used right now but
        // will be helpful later when we want to download partial block contents.
        //
        // Note that if the number of transactions is not even the last tx is repeated to make it so (see
        // tx3 above). A tree with 5 transactions would look like this:
        //
        //         root
        //        /     \
        //       1        5
        //     /   \     / \
        //    2     3    4  4
        //  / \   / \   / \
        // t1 t2 t3 t4 t5 t5
        val tree = ArrayList<ByteArray>()
        // Start by adding all the hashes of the transactions as leaves of the tree.
        for (t in transactions!!) {
            tree.add(t.hash!!.bytes)
        }
        var levelOffset = 0 // Offset in the list where the currently processed level starts.
        // Step through each level, stopping when we reach the root (levelSize == 1).
        var levelSize = transactions!!.size
        while (levelSize > 1) {
            // For each pair of nodes on that level:
            var left = 0
            while (left < levelSize) {
                // The right hand node can be the same as the left hand, in the case where we don't have enough
                // transactions.
                val right = Math.min(left + 1, levelSize - 1)
                val leftBytes = Utils.reverseBytes(tree[levelOffset + left])
                val rightBytes = Utils.reverseBytes(tree[levelOffset + right])
                tree.add(Utils.reverseBytes(Sha256Hash.hashTwice(leftBytes, 0, 32, rightBytes, 0, 32)))
                left += 2
            }
            // Move to the next level.
            levelOffset += levelSize
            levelSize = (levelSize + 1) / 2
        }
        return tree
    }

    /**
     * Verify the transactions on a block.
     *
     * @param height block height, if known, or -1 otherwise. If provided, used
     * to validate the coinbase input script of v2 and above blocks.
     * @throws VerificationException if there was an error verifying the block.
     */
    @Throws(VerificationException::class)
    private fun checkTransactions(height: Int, flags: EnumSet<VerifyFlag>) {
        // The first transaction in a block must always be a coinbase transaction.
        if (!transactions!![0].isCoinBase)
            throw VerificationException("First tx is not coinbase")
        if (flags.contains(Block.VerifyFlag.HEIGHT_IN_COINBASE) && height >= BLOCK_HEIGHT_GENESIS) {
            transactions!![0].checkCoinBaseHeight(height)
        }
        // The rest must not be.
        for (i in 1 until transactions!!.size) {
            if (transactions!![i].isCoinBase)
                throw VerificationException("TX $i is coinbase when it should not be.")
        }
    }

    /**
     * Checks the block data to ensure it follows the rules laid out in the network parameters. Specifically,
     * throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
     * This is **not** everything that is required for a block to be valid, only what is checkable independent
     * of the chain and without a transaction index.
     *
     * @throws VerificationException
     */
    @Throws(VerificationException::class)
    fun verifyHeader() {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
        checkProofOfWork(true)
        checkTimestamp()
    }

    /**
     * Checks the block contents
     *
     * @param height block height, if known, or -1 otherwise. If valid, used
     * to validate the coinbase input script of v2 and above blocks.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if there was an error verifying the block.
     */
    @Throws(VerificationException::class)
    fun verifyTransactions(height: Int, flags: EnumSet<VerifyFlag>) {
        // Now we need to check that the body of the block actually matches the headers. The network won't generate
        // an invalid block, but if we didn't validate this then an untrusted man-in-the-middle could obtain the next
        // valid block from the network and simply replace the transactions in it with their own fictional
        // transactions that reference spent or non-existant inputs.
        if (transactions!!.isEmpty())
            throw VerificationException("Block had no transactions")
        if (this.optimalEncodingMessageSize > MAX_BLOCK_SIZE)
            throw VerificationException("Block larger than MAX_BLOCK_SIZE")
        checkTransactions(height, flags)
        checkMerkleRoot()
        checkSigOps()
        for (transaction in transactions!!)
            transaction.verify()
    }

    /**
     * Verifies both the header and that the transactions hash to the merkle root.
     *
     * @param height block height, if known, or -1 otherwise.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if there was an error verifying the block.
     */
    @Throws(VerificationException::class)
    fun verify(height: Int, flags: EnumSet<VerifyFlag>) {
        verifyHeader()
        verifyTransactions(height, flags)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        return if (o == null || javaClass != o.javaClass) false else hash == (o as Block).hash
    }

    override fun hashCode(): Int {
        return hash!!.hashCode()
    }

    /**
     * Returns the merkle root in big endian form, calculating it from transactions if necessary.
     */
    fun getMerkleRoot(): Sha256Hash {
        if (merkleRoot == null) {
            //TODO check if this is really necessary.
            unCacheHeader()
            merkleRoot = calculateMerkleRoot()
        }
        return merkleRoot as Sha256Hash
    }

    /** Exists only for unit testing.  */
    internal fun setMerkleRoot(value: Sha256Hash) {
        unCacheHeader()
        merkleRoot = value
        hash = null
    }

    /** Adds a transaction to this block. The nonce and merkle root are invalid after this.  */
    fun addTransaction(t: Transaction) {
        addTransaction(t, true)
    }

    /** Adds a transaction to this block, with or without checking the sanity of doing so  */
    internal fun addTransaction(t: Transaction, runSanityChecks: Boolean) {
        unCacheTransactions()
        if (transactions == null) {
            transactions = ArrayList()
        }
        t.parent = (this)
        if (runSanityChecks && transactions!!.size == 0 && !t.isCoinBase)
            throw RuntimeException("Attempted to add a non-coinbase transaction as the first transaction: " + t)
        else if (runSanityChecks && transactions!!.size > 0 && t.isCoinBase)
            throw RuntimeException("Attempted to add a coinbase transaction when there already is one: " + t)
        transactions!!.add(t)
        adjustLength(transactions!!.size, t.length)
        // Force a recalculation next time the values are needed.
        merkleRoot = null
        hash = null
    }

    /**
     * Returns the hash of the previous block in the chain, as defined by the block header.
     */
    fun getPrevBlockHash(): Sha256Hash? {
        return prevBlockHash
    }

    internal fun setPrevBlockHash(prevBlockHash: Sha256Hash) {
        unCacheHeader()
        this.prevBlockHash = prevBlockHash
        this.hash = null
    }

    fun setTime(time: Long) {
        unCacheHeader()
        this.timeSeconds = time
        this.hash = null
    }

    /**
     * Returns the difficulty of the proof of work that this block should meet encoded **in compact form**. The [ ] verifies that this is not too easy by looking at the length of the chain when the block is added.
     * To find the actual value the hash should be compared against, use
     * [org.bitcoinj.core.Block.getDifficultyTargetAsInteger]. Note that this is **not** the same as
     * the difficulty value reported by the Bitcoin "getdifficulty" RPC that you may see on various block explorers.
     * That number is the result of applying a formula to the underlying difficulty to normalize the minimum to 1.
     * Calculating the difficulty that way is currently unsupported.
     */
    fun getDifficultyTarget(): Long {
        return difficultyTarget
    }

    /** Sets the difficulty target in compact form.  */
    fun setDifficultyTarget(compactForm: Long) {
        unCacheHeader()
        this.difficultyTarget = compactForm
        this.hash = null
    }

    /**
     * Returns the nonce, an arbitrary value that exists only to make the hash of the block header fall below the
     * difficulty target.
     */
    fun getNonce(): Long {
        return nonce
    }

    /** Sets the nonce and clears any cached data.  */
    fun setNonce(nonce: Long) {
        unCacheHeader()
        this.nonce = nonce
        this.hash = null
    }

    /** Returns an immutable list of transactions held in this block, or null if this object represents just a header.  */
    fun getTransactions(): List<Transaction>? {
        return if (transactions == null) null else ImmutableList.copyOf(transactions!!)
    }

    /** Adds a coinbase transaction to the block. This exists for unit tests.
     *
     * @param height block height, if known, or -1 otherwise.
     */
    @VisibleForTesting
    internal fun addCoinbaseTransaction(pubKeyTo: ByteArray, value: Coin, height: Int) {
        unCacheTransactions()
        transactions = ArrayList()
        val coinbase = Transaction(params!!)
        val inputBuilder = ScriptBuilder()

        if (height >= Block.BLOCK_HEIGHT_GENESIS) {
            inputBuilder.number(height.toLong())
        }
        inputBuilder.data(byteArrayOf(txCounter.toByte(), (txCounter++ shr 8).toByte()))

        // A real coinbase transaction has some stuff in the scriptSig like the extraNonce and difficulty. The
        // transactions are distinguished by every TX output going to a different key.
        //
        // Here we will do things a bit differently so a new address isn't needed every time. We'll put a simple
        // counter in the scriptSig so every transaction has a different hash.
        coinbase.addInput(TransactionInput(params!!, coinbase,
                inputBuilder.build().program))
        coinbase.addOutput(TransactionOutput(params!!, coinbase, value,
                ScriptBuilder.createOutputScript(ECKey.fromPublicOnly(pubKeyTo)).program))
        transactions!!.add(coinbase)
        coinbase.parent = (this)
        coinbase.length = coinbase.unsafeBitcoinSerialize().size
        adjustLength(transactions!!.size, coinbase.length)
    }

    /**
     * Returns a solved block that builds on top of this one. This exists for unit tests.
     */
    @VisibleForTesting
    fun createNextBlock(to: Address, version: Long, time: Long, blockHeight: Int): Block {
        return createNextBlock(to, version, null, time, pubkeyForTesting, Coin.FIFTY_COINS, blockHeight)
    }

    /**
     * Returns a solved block that builds on top of this one. This exists for unit tests.
     * In this variant you can specify a public key (pubkey) for use in generating coinbase blocks.
     *
     * @param height block height, if known, or -1 otherwise.
     */
    internal fun createNextBlock(to: Address?, version: Long,
                                 prevOut: TransactionOutPoint?, time: Long,
                                 pubKey: ByteArray, coinbaseValue: Coin,
                                 height: Int): Block {
        val b = Block(params!!, version)
        b.setDifficultyTarget(difficultyTarget)
        b.addCoinbaseTransaction(pubKey, coinbaseValue, height)

        if (to != null) {
            // Add a transaction paying 50 coins to the "to" address.
            val t = Transaction(params!!)
            t.addOutput(TransactionOutput(params!!, t, Coin.FIFTY_COINS, to))
            // The input does not really need to be a valid signature, as long as it has the right general form.
            val input: TransactionInput
            if (prevOut == null) {
                input = TransactionInput(params!!, t, Script.createInputScript(EMPTY_BYTES, EMPTY_BYTES))
                // Importantly the outpoint hash cannot be zero as that's how we detect a coinbase transaction in isolation
                // but it must be unique to avoid 'different' transactions looking the same.
                val counter = ByteArray(32)
                counter[0] = txCounter.toByte()
                counter[1] = (txCounter++ shr 8).toByte()
                input.outpoint!!.hash = Sha256Hash.wrap(counter)
            } else {
                input = TransactionInput(params!!, t, Script.createInputScript(EMPTY_BYTES, EMPTY_BYTES), prevOut)
            }
            t.addInput(input)
            b.addTransaction(t)
        }

        b.setPrevBlockHash(hash!!)
        // Don't let timestamp go backwards
        if (timeSeconds >= time)
            b.setTime(timeSeconds + 1)
        else
            b.setTime(time)
        b.solve()
        try {
            b.verifyHeader()
        } catch (e: VerificationException) {
            throw RuntimeException(e) // Cannot happen.
        }

        if (b.version != version) {
            throw RuntimeException()
        }
        return b
    }

    @VisibleForTesting
    fun createNextBlock(to: Address?, prevOut: TransactionOutPoint): Block {
        return createNextBlock(to, BLOCK_VERSION_GENESIS, prevOut, timeSeconds + 5, pubkeyForTesting, Coin.FIFTY_COINS, BLOCK_HEIGHT_UNKNOWN)
    }

    @VisibleForTesting
    @JvmOverloads
    fun createNextBlock(to: Address?, value: Coin = Coin.FIFTY_COINS): Block {
        return createNextBlock(to, BLOCK_VERSION_GENESIS, null, timeSeconds + 5, pubkeyForTesting, value, BLOCK_HEIGHT_UNKNOWN)
    }

    @VisibleForTesting
    fun createNextBlockWithCoinbase(version: Long, pubKey: ByteArray, coinbaseValue: Coin, height: Int): Block {
        return createNextBlock(null, version, null as TransactionOutPoint?,
                Utils.currentTimeSeconds(), pubKey, coinbaseValue, height)
    }

    /**
     * Create a block sending 50BTC as a coinbase transaction to the public key specified.
     * This method is intended for test use only.
     */
    @VisibleForTesting
    internal fun createNextBlockWithCoinbase(version: Long, pubKey: ByteArray, height: Int): Block {
        return createNextBlock(null, version, null as TransactionOutPoint?,
                Utils.currentTimeSeconds(), pubKey, Coin.FIFTY_COINS, height)
    }

    /**
     * Return whether this block contains any transactions.
     *
     * @return  true if the block contains transactions, false otherwise (is
     * purely a header).
     */
    fun hasTransactions(): Boolean {
        return !this.transactions!!.isEmpty()
    }

    companion object {

        private val log = LoggerFactory.getLogger(Block::class.java!!)

        /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte.  */
        val HEADER_SIZE = 80

        internal val ALLOWED_TIME_DRIFT = (2 * 60 * 60).toLong() // Same value as Bitcoin Core.

        /**
         * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
         * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
         * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
         */
        val MAX_BLOCK_SIZE = 8 * 1000 * 1000
        /**
         * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
         * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
         * expensive/slow to verify.
         */
        val MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50

        /** A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing.  */
        val EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL

        /** Value to use if the block height is unknown  */
        val BLOCK_HEIGHT_UNKNOWN = -1
        /** Height of the first block  */
        val BLOCK_HEIGHT_GENESIS = 0

        val BLOCK_VERSION_GENESIS: Long = 1
        /** Block version introduced in BIP 34: Height in coinbase  */
        val BLOCK_VERSION_BIP34: Long = 2
        /** Block version introduced in BIP 66: Strict DER signatures  */
        val BLOCK_VERSION_BIP66: Long = 3
        /** Block version introduced in BIP 65: OP_CHECKLOCKTIMEVERIFY  */
        val BLOCK_VERSION_BIP65: Long = 4

        /**
         * The number that is one greater than the largest representable SHA-256
         * hash.
         */
        private val LARGEST_HASH = BigInteger.ONE.shiftLeft(256)

        // ///////////////////////////////////////////////////////////////////////////////////////////////
        // Unit testing related methods.

        // Used to make transactions unique.
        private var txCounter: Int = 0

        internal val EMPTY_BYTES = ByteArray(32)

        // It's pretty weak to have this around at runtime: fix later.
        private val pubkeyForTesting = ECKey().pubKey
    }
}
