/*
 * Copyright 2012 Google Inc.
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

import com.google.common.base.*
import com.google.common.collect.*
import com.google.common.util.concurrent.*
import org.bitcoinj.core.listeners.*
import org.bitcoinj.store.*
import org.bitcoinj.utils.*
import org.bitcoinj.wallet.Wallet
import org.slf4j.*

import javax.annotation.*
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.locks.*

import com.google.common.base.Preconditions.*

/**
 *
 * An AbstractBlockChain holds a series of [Block] objects, links them together, and knows how to verify that
 * the chain follows the rules of the [NetworkParameters] for this chain.
 *
 *
 * It can be connected to a [Wallet], and also [TransactionReceivedInBlockListener]s that can receive transactions and
 * notifications of re-organizations.
 *
 *
 * An AbstractBlockChain implementation must be connected to a [BlockStore] implementation. The chain object
 * by itself doesn't store any data, that's delegated to the store. Which store you use is a decision best made by
 * reading the getting started guide, but briefly, fully validating block chains need fully validating stores. In
 * the lightweight SPV mode, a [org.bitcoinj.store.SPVBlockStore] is the right choice.
 *
 *
 * This class implements an abstract class which makes it simple to create a BlockChain that does/doesn't do full
 * verification.  It verifies headers and is implements most of what is required to implement SPV mode, but
 * also provides callback hooks which can be used to do full verification.
 *
 *
 * There are two subclasses of AbstractBlockChain that are useful: [BlockChain], which is the simplest
 * class and implements *simplified payment verification*. This is a lightweight and efficient mode that does
 * not verify the contents of blocks, just their headers. A [FullPrunedBlockChain] paired with a
 * [org.bitcoinj.store.H2FullPrunedBlockStore] implements full verification, which is equivalent to
 * Bitcoin Core. To learn more about the alternative security models, please consult the articles on the
 * website.
 *
 * **Theory**
 *
 *
 * The 'chain' is actually a tree although in normal operation it operates mostly as a list of [Block]s.
 * When multiple new head blocks are found simultaneously, there are multiple stories of the economy competing to become
 * the one true consensus. This can happen naturally when two miners solve a block within a few seconds of each other,
 * or it can happen when the chain is under attack.
 *
 *
 * A reference to the head block of the best known chain is stored. If you can reach the genesis block by repeatedly
 * walking through the prevBlock pointers, then we say this is a full chain. If you cannot reach the genesis block
 * we say it is an orphan chain. Orphan chains can occur when blocks are solved and received during the initial block
 * chain download, or if we connect to a peer that doesn't send us blocks in order.
 *
 *
 * A reorganize occurs when the blocks that make up the best known chain changes. Note that simply adding a
 * new block to the top of the best chain isn't as reorganize, but that a reorganize is always triggered by adding
 * a new block that connects to some other (non best head) block. By "best" we mean the chain representing the largest
 * amount of work done.
 *
 *
 * Every so often the block chain passes a difficulty transition point. At that time, all the blocks in the last
 * 2016 blocks are examined and a new difficulty target is calculated from them.
 */
abstract class AbstractBlockChain
/**
 * Constructs a BlockChain connected to the given list of listeners (eg, wallets) and a store.
 */
@Throws(BlockStoreException::class)
constructor(context: Context, wallets: List<Wallet>,
        /** Keeps a map of block hashes to StoredBlocks.  */
            /**
             * Returns the [BlockStore] the chain was constructed with. You can use this to iterate over the chain.
             */
           open val blockStore: BlockStore) {
    protected val lock = Threading.lock("blockchain")

    /**
     * Tracks the top of the best known chain.
     *
     *
     *
     * Following this one down to the genesis block produces the story of the economy from the creation of Bitcoin
     * until the present day. The chain head can change if a new set of blocks is received that results in a chain of
     * greater work than the one obtained by following this one down. In that case a reorganize is triggered,
     * potentially invalidating transactions in our wallet.
     */
    protected var chainHead: StoredBlock
    /**
     * Returns the block at the head of the current best chain. This is the block which represents the greatest
     * amount of cumulative work done.
     */
        get(): StoredBlock {
            synchronized(chainHeadLock) {
                return chainHead
            }
        }
        @Throws(BlockStoreException::class)
        set(chainHead: StoredBlock) {
            doSetChainHead(chainHead)
            synchronized(chainHeadLock) {
                this.chainHead = chainHead
            }
        }
    // TODO: Scrap this and use a proper read/write for all of the block chain objects.
    // The chainHead field is read/written synchronized with this object rather than BlockChain. However writing is
    // also guaranteed to happen whilst BlockChain is synchronized (see setChainHead). The goal of this is to let
    // clients quickly access the chain head even whilst the block chain is downloading and thus the BlockChain is
    // locked most of the time.
    private val chainHeadLock = Any()

    protected val params: NetworkParameters
    private val newBestBlockListeners: CopyOnWriteArrayList<ListenerRegistration<NewBestBlockListener>>
    private val reorganizeListeners: CopyOnWriteArrayList<ListenerRegistration<ReorganizeListener>>
    private val transactionReceivedListeners: CopyOnWriteArrayList<ListenerRegistration<TransactionReceivedInBlockListener>>
    // Holds blocks that we have received but can't plug into the chain yet, eg because they were created whilst we
    // were downloading the block chain.
    private val orphanBlocks = LinkedHashMap<Sha256Hash, OrphanBlock>()

    /**
     * The false positive rate is the average over all blockchain transactions of:
     *
     * - 1.0 if the transaction was false-positive (was irrelevant to all listeners)
     * - 0.0 if the transaction was relevant or filtered out
     */
    var falsePositiveRate: Double = 0.toDouble()
        private set
    private var falsePositiveTrend: Double = 0.toDouble()
    private var previousFalsePositiveRate: Double = 0.toDouble()

    protected val versionTally: VersionTally

    /**
     * @return the height of the best known chain, convenience for <tt>getChainHead().getHeight()</tt>.
     */
    val bestChainHeight: Int
        get() = chainHead.height

    // Holds a block header and, optionally, a list of tx hashes or block's transactions
    internal inner class OrphanBlock(val block: Block, val filteredTxHashes: List<Sha256Hash>?, val filteredTxn: Map<Sha256Hash, Transaction>?) {
        init {
            val filtered = filteredTxHashes != null && filteredTxn != null
            Preconditions.checkArgument(block.transactions == null && filtered || block.transactions != null && !filtered)
        }
    }

    /** See [.AbstractBlockChain]  */
    @Throws(BlockStoreException::class)
    constructor(params: NetworkParameters, transactionReceivedListeners: List<Wallet>,
                blockStore: BlockStore) : this(Context.getOrCreate(params), transactionReceivedListeners, blockStore) {
    }

    init {
        chainHead = blockStore.chainHead
        log.info("chain head is at height {}:\n{}", chainHead.height, chainHead.header)
        this.params = context.params

        this.newBestBlockListeners = CopyOnWriteArrayList()
        this.reorganizeListeners = CopyOnWriteArrayList()
        this.transactionReceivedListeners = CopyOnWriteArrayList()
        for (l in wallets) addNewBestBlockListener(Threading.SAME_THREAD, l)
        for (l in wallets) addReorganizeListener(Threading.SAME_THREAD, l)
        for (l in wallets) addTransactionReceivedListener(Threading.SAME_THREAD, l)

        this.versionTally = VersionTally(context.params)
        this.versionTally.initialize(blockStore, chainHead)
    }

    /**
     * Add a wallet to the BlockChain. Note that the wallet will be unaffected by any blocks received while it
     * was not part of this BlockChain. This method is useful if the wallet has just been created, and its keys
     * have never been in use, or if the wallet has been loaded along with the BlockChain. Note that adding multiple
     * wallets is not well tested!
     */
    fun addWallet(wallet: Wallet) {
        addNewBestBlockListener(Threading.SAME_THREAD, wallet)
        addReorganizeListener(Threading.SAME_THREAD, wallet)
        addTransactionReceivedListener(Threading.SAME_THREAD, wallet)
        val walletHeight = wallet.lastBlockSeenHeight
        val chainHeight = bestChainHeight
        if (walletHeight != chainHeight) {
            log.warn("Wallet/chain height mismatch: {} vs {}", walletHeight, chainHeight)
            log.warn("Hashes: {} vs {}", wallet.lastBlockSeenHash, chainHead.header.hash)

            // This special case happens when the VM crashes because of a transaction received. It causes the updated
            // block store to persist, but not the wallet. In order to fix the issue, we roll back the block store to
            // the wallet height to make it look like as if the block has never been received.
            if (walletHeight < chainHeight && walletHeight > 0) {
                try {
                    rollbackBlockStore(walletHeight)
                    log.info("Rolled back block store to height {}.", walletHeight)
                } catch (x: BlockStoreException) {
                    log.warn("Rollback of block store failed, continuing with mismatched heights. This can happen due to a replay.")
                }

            }
        }
    }

    /** Removes a wallet from the chain.  */
    fun removeWallet(wallet: Wallet) {
        removeNewBestBlockListener(wallet)
        removeReorganizeListener(wallet)
        removeTransactionReceivedListener(wallet)
    }

    /** Replaced with more specific listener methods: use them instead.  */
    @Deprecated("")
    fun addListener(listener: BlockChainListener) {
        addListener(listener, Threading.USER_THREAD)
    }

    /** Replaced with more specific listener methods: use them instead.  */
    @Deprecated("")
    fun addListener(listener: BlockChainListener, executor: Executor) {
        addReorganizeListener(executor, listener)
        addNewBestBlockListener(executor, listener)
        addTransactionReceivedListener(executor, listener)
    }

    @Deprecated("")
    fun removeListener(listener: BlockChainListener) {
        removeReorganizeListener(listener)
        removeNewBestBlockListener(listener)
        removeTransactionReceivedListener(listener)
    }

    /**
     * Adds a [NewBestBlockListener] listener to the chain.
     */
    fun addNewBestBlockListener(listener: NewBestBlockListener) {
        addNewBestBlockListener(Threading.USER_THREAD, listener)
    }

    /**
     * Adds a [NewBestBlockListener] listener to the chain.
     */
    fun addNewBestBlockListener(executor: Executor, listener: NewBestBlockListener) {
        newBestBlockListeners.add(ListenerRegistration(listener, executor))
    }

    /**
     * Adds a generic [ReorganizeListener] listener to the chain.
     */
    fun addReorganizeListener(listener: ReorganizeListener) {
        addReorganizeListener(Threading.USER_THREAD, listener)
    }

    /**
     * Adds a generic [ReorganizeListener] listener to the chain.
     */
    fun addReorganizeListener(executor: Executor, listener: ReorganizeListener) {
        reorganizeListeners.add(ListenerRegistration(listener, executor))
    }

    /**
     * Adds a generic [TransactionReceivedInBlockListener] listener to the chain.
     */
    fun addTransactionReceivedListener(listener: TransactionReceivedInBlockListener) {
        addTransactionReceivedListener(Threading.USER_THREAD, listener)
    }

    /**
     * Adds a generic [TransactionReceivedInBlockListener] listener to the chain.
     */
    fun addTransactionReceivedListener(executor: Executor, listener: TransactionReceivedInBlockListener) {
        transactionReceivedListeners.add(ListenerRegistration(listener, executor))
    }

    /**
     * Removes the given [NewBestBlockListener] from the chain.
     */
    fun removeNewBestBlockListener(listener: NewBestBlockListener) {
        ListenerRegistration.removeFromList(listener, newBestBlockListeners)
    }

    /**
     * Removes the given [ReorganizeListener] from the chain.
     */
    fun removeReorganizeListener(listener: ReorganizeListener) {
        ListenerRegistration.removeFromList(listener, reorganizeListeners)
    }

    /**
     * Removes the given [TransactionReceivedInBlockListener] from the chain.
     */
    fun removeTransactionReceivedListener(listener: TransactionReceivedInBlockListener) {
        ListenerRegistration.removeFromList(listener, transactionReceivedListeners)
    }

    /**
     * Adds/updates the given [Block] with the block store.
     * This version is used when the transactions have not been verified.
     * @param storedPrev The [StoredBlock] which immediately precedes block.
     * @param block The [Block] to add/update.
     * @return the newly created [StoredBlock]
     */
    @Throws(BlockStoreException::class, VerificationException::class)
    protected abstract fun addToBlockStore(storedPrev: StoredBlock, block: Block): StoredBlock

    /**
     * Adds/updates the given [StoredBlock] with the block store.
     * This version is used when the transactions have already been verified to properly spend txOutputChanges.
     * @param storedPrev The [StoredBlock] which immediately precedes block.
     * @param header The [StoredBlock] to add/update.
     * @param txOutputChanges The total sum of all changes made by this block to the set of open transaction outputs
     * (from a call to connectTransactions), if in fully verifying mode (null otherwise).
     * @return the newly created [StoredBlock]
     */
    @Throws(BlockStoreException::class, VerificationException::class)
    protected abstract fun addToBlockStore(storedPrev: StoredBlock, header: Block,
                                           txOutputChanges: TransactionOutputChanges?): StoredBlock

    /**
     * Rollback the block store to a given height. This is currently only supported by [BlockChain] instances.
     *
     * @throws BlockStoreException
     * if the operation fails or is unsupported.
     */
    @Throws(BlockStoreException::class)
    protected abstract fun rollbackBlockStore(height: Int)

    /**
     * Called before setting chain head in memory.
     * Should write the new head to block store and then commit any database transactions
     * that were started by disconnectTransactions/connectTransactions.
     */
    @Throws(BlockStoreException::class)
    protected abstract fun doSetChainHead(chainHead: StoredBlock)

    /**
     * Called if we (possibly) previously called disconnectTransaction/connectTransactions,
     * but will not be calling preSetChainHead as a block failed verification.
     * Can be used to abort database transactions that were started by
     * disconnectTransactions/connectTransactions.
     */
    @Throws(BlockStoreException::class)
    protected abstract fun notSettingChainHead()

    /**
     * For a standard BlockChain, this should return blockStore.get(hash),
     * for a FullPrunedBlockChain blockStore.getOnceUndoableStoredBlock(hash)
     */
    @Throws(BlockStoreException::class)
    protected abstract fun getStoredBlockInCurrentScope(hash: Sha256Hash?): StoredBlock?

    /**
     * Processes a received block and tries to add it to the chain. If there's something wrong with the block an
     * exception is thrown. If the block is OK but cannot be connected to the chain at this time, returns false.
     * If the block can be connected to the chain, returns true.
     * Accessing block's transactions in another thread while this method runs may result in undefined behavior.
     */
    @Throws(VerificationException::class, PrunedException::class)
    fun add(block: Block): Boolean {
        try {
            return add(block, true, null, null)
        } catch (e: BlockStoreException) {
            // TODO: Figure out a better way to propagate this exception to the user.
            throw RuntimeException(e)
        } catch (e: VerificationException) {
            try {
                notSettingChainHead()
            } catch (e1: BlockStoreException) {
                throw RuntimeException(e1)
            }

            throw VerificationException("Could not verify block:\n" + block.toString(), e)
        }

    }

    /**
     * Processes a received block and tries to add it to the chain. If there's something wrong with the block an
     * exception is thrown. If the block is OK but cannot be connected to the chain at this time, returns false.
     * If the block can be connected to the chain, returns true.
     */
    @Throws(VerificationException::class, PrunedException::class)
    open fun add(block: FilteredBlock): Boolean {
        try {
            // The block has a list of hashes of transactions that matched the Bloom filter, and a list of associated
            // Transaction objects. There may be fewer Transaction objects than hashes, this is expected. It can happen
            // in the case where we were already around to witness the initial broadcast, so we downloaded the
            // transaction and sent it to the wallet before this point (the wallet may have thrown it away if it was
            // a false positive, as expected in any Bloom filtering scheme). The filteredTxn list here will usually
            // only be full of data when we are catching up to the head of the chain and thus haven't witnessed any
            // of the transactions.
            return add(block.blockHeader, true, block.transactionHashes, block.getAssociatedTransactions())
        } catch (e: BlockStoreException) {
            // TODO: Figure out a better way to propagate this exception to the user.
            throw RuntimeException(e)
        } catch (e: VerificationException) {
            try {
                notSettingChainHead()
            } catch (e1: BlockStoreException) {
                throw RuntimeException(e1)
            }

            throw VerificationException("Could not verify block " + block.hash.toString() + "\n" +
                    block.toString(), e)
        }

    }

    /**
     * Whether or not we are maintaining a set of unspent outputs and are verifying all transactions.
     * Also indicates that all calls to add() should provide a block containing transactions
     */
    abstract fun shouldVerifyTransactions(): Boolean

    /**
     * Connect each transaction in block.transactions, verifying them as we go and removing spent outputs
     * If an error is encountered in a transaction, no changes should be made to the underlying BlockStore.
     * and a VerificationException should be thrown.
     * Only called if(shouldVerifyTransactions())
     * @throws VerificationException if an attempt was made to spend an already-spent output, or if a transaction incorrectly solved an output script.
     * @throws BlockStoreException if the block store had an underlying error.
     * @return The full set of all changes made to the set of open transaction outputs.
     */
    @Throws(VerificationException::class, BlockStoreException::class)
    abstract fun connectTransactions(height: Int, block: Block): TransactionOutputChanges

    /**
     * Load newBlock from BlockStore and connect its transactions, returning changes to the set of unspent transactions.
     * If an error is encountered in a transaction, no changes should be made to the underlying BlockStore.
     * Only called if(shouldVerifyTransactions())
     * @throws PrunedException if newBlock does not exist as a [StoredUndoableBlock] in the block store.
     * @throws VerificationException if an attempt was made to spend an already-spent output, or if a transaction incorrectly solved an output script.
     * @throws BlockStoreException if the block store had an underlying error or newBlock does not exist in the block store at all.
     * @return The full set of all changes made to the set of open transaction outputs.
     */
    @Throws(VerificationException::class, BlockStoreException::class, PrunedException::class)
    protected abstract fun connectTransactions(newBlock: StoredBlock): TransactionOutputChanges

    // filteredTxHashList contains all transactions, filteredTxn just a subset
    @Throws(BlockStoreException::class, VerificationException::class, PrunedException::class)
    private fun add(block: Block, tryConnecting: Boolean,
                    filteredTxHashList: List<Sha256Hash>?, filteredTxn: Map<Sha256Hash, Transaction>?): Boolean {
        // TODO: Use read/write locks to ensure that during chain download properties are still low latency.
        lock.lock()
        try {
            // Quick check for duplicates to avoid an expensive check further down (in findSplit). This can happen a lot
            // when connecting orphan transactions due to the dumb brute force algorithm we use.
            if (block == chainHead.header) {
                return true
            }
            if (tryConnecting && orphanBlocks.containsKey(block.hash)) {
                return false
            }

            // If we want to verify transactions (ie we are running with full blocks), verify that block has transactions
            if (shouldVerifyTransactions() && block.transactions == null)
                throw VerificationException("Got a block header while running in full-block mode")

            // Check for already-seen block, but only for full pruned mode, where the DB is
            // more likely able to handle these queries quickly.
            if (shouldVerifyTransactions() && blockStore.get(block.hash) != null) {
                return true
            }

            val storedPrev: StoredBlock?
            val height: Int
            val flags: EnumSet<Block.VerifyFlag>

            // Prove the block is internally valid: hash is lower than target, etc. This only checks the block contents
            // if there is a tx sending or receiving coins using an address in one of our wallets. And those transactions
            // are only lightly verified: presence in a valid connecting block is taken as proof of validity. See the
            // article here for more details: https://bitcoinj.github.io/security-model
            try {
                block.verifyHeader()
                storedPrev = getStoredBlockInCurrentScope(block.getPrevBlockHash())
                if (storedPrev != null) {
                    height = storedPrev.height + 1
                } else {
                    height = Block.BLOCK_HEIGHT_UNKNOWN
                }
                flags = params.getBlockVerificationFlags(block, versionTally, height)
                if (shouldVerifyTransactions())
                    block.verifyTransactions(height, flags)
            } catch (e: VerificationException) {
                log.error("Failed to verify block: ", e)
                log.error(block.hashAsString)
                throw e
            }

            // Try linking it to a place in the currently known blocks.

            if (storedPrev == null) {
                // We can't find the previous block. Probably we are still in the process of downloading the chain and a
                // block was solved whilst we were doing it. We put it to one side and try to connect it later when we
                // have more blocks.
                checkState(tryConnecting, "bug in tryConnectingOrphans")
                log.warn("Block does not connect: {} prev {}", block.hashAsString, block.getPrevBlockHash())
                orphanBlocks.put(block.hash!!, OrphanBlock(block, filteredTxHashList, filteredTxn))
                return false
            } else {
                checkState(lock.isHeldByCurrentThread)
                // It connects to somewhere on the chain. Not necessarily the top of the best known chain.
                params.checkDifficultyTransitions(storedPrev, block, blockStore, this)
                connectBlock(block, storedPrev, shouldVerifyTransactions(), filteredTxHashList, filteredTxn)
            }

            if (tryConnecting)
                tryConnectingOrphans()

            return true
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns the hashes of the currently stored orphan blocks and then deletes them from this objects storage.
     * Used by Peer when a filter exhaustion event has occurred and thus any orphan blocks that have been downloaded
     * might be inaccurate/incomplete.
     */
    fun drainOrphanBlocks(): Set<Sha256Hash> {
        lock.lock()
        try {
            val hashes = HashSet(orphanBlocks.keys)
            orphanBlocks.clear()
            return hashes
        } finally {
            lock.unlock()
        }
    }

    // expensiveChecks enables checks that require looking at blocks further back in the chain
    // than the previous one when connecting (eg median timestamp check)
    // It could be exposed, but for now we just set it to shouldVerifyTransactions()
    @Throws(BlockStoreException::class, VerificationException::class, PrunedException::class)
    private fun connectBlock(block: Block, storedPrev: StoredBlock, expensiveChecks: Boolean,
                             filteredTxHashList: List<Sha256Hash>?,
                             filteredTxn: Map<Sha256Hash, Transaction>?) {
        checkState(lock.isHeldByCurrentThread)
        val filtered = filteredTxHashList != null && filteredTxn != null
        // Check that we aren't connecting a block that fails a checkpoint check
        if (!params.passesCheckpoint(storedPrev.height + 1, block.hash!!))
            throw VerificationException("Block failed checkpoint lockin at " + (storedPrev.height + 1))
        if (shouldVerifyTransactions()) {
            checkNotNull<List<Transaction>>(block.transactions)
            for (tx in block.transactions!!)
                if (!tx.isFinal(storedPrev.height + 1, block.timeSeconds))
                    throw VerificationException("Block contains non-final transaction")
        }

        val head = chainHead
        if (storedPrev == head) {
            if (filtered && filteredTxn!!.size > 0) {
                log.debug("Block {} connects to top of best chain with {} transaction(s) of which we were sent {}",
                        block.hashAsString, filteredTxHashList!!.size, filteredTxn.size)
                for (hash in filteredTxHashList) log.debug("  matched tx {}", hash)
            }
            if (expensiveChecks && block.timeSeconds <= getMedianTimestampOfRecentBlocks(head, blockStore))
                throw VerificationException("Block's timestamp is too early")

            // BIP 66 & 65: Enforce block version 3/4 once they are a supermajority of blocks
            // NOTE: This requires 1,000 blocks since the last checkpoint (on main
            // net, less on test) in order to be applied. It is also limited to
            // stopping addition of new v2/3 blocks to the tip of the chain.
            if (block.version == Block.BLOCK_VERSION_BIP34 || block.version == Block.BLOCK_VERSION_BIP66) {
                val count = versionTally.getCountAtOrAbove(block.version + 1)
                if (count != null && count >= params.majorityRejectBlockOutdated) {
                    throw VerificationException.BlockVersionOutOfDate(block.version)
                }
            }

            // This block connects to the best known block, it is a normal continuation of the system.
            var txOutChanges: TransactionOutputChanges? = null
            if (shouldVerifyTransactions())
                txOutChanges = connectTransactions(storedPrev.height + 1, block)
            val newStoredBlock = addToBlockStore(storedPrev,
                    if (block.transactions == null) block else block.cloneAsHeader(), txOutChanges)
            versionTally.add(block.version)
            chainHead = newStoredBlock
            log.debug("Chain is now {} blocks high, running listeners", newStoredBlock.height)
            informListenersForNewBlock(block, NewBlockType.BEST_CHAIN, filteredTxHashList, filteredTxn, newStoredBlock)
        } else {
            // This block connects to somewhere other than the top of the best known chain. We treat these differently.
            //
            // Note that we send the transactions to the wallet FIRST, even if we're about to re-organize this block
            // to become the new best chain head. This simplifies handling of the re-org in the Wallet class.
            val newBlock = storedPrev.build(block)
            val haveNewBestChain = newBlock.moreWorkThan(head)
            if (haveNewBestChain) {
                log.info("Block is causing a re-organize")
            } else {
                val splitPoint = findSplit(newBlock, head, blockStore)
                if (splitPoint != null && splitPoint == newBlock) {
                    // newStoredBlock is a part of the same chain, there's no fork. This happens when we receive a block
                    // that we already saw and linked into the chain previously, which isn't the chain head.
                    // Re-processing it is confusing for the wallet so just skip.
                    log.warn("Saw duplicated block in main chain at height {}: {}",
                            newBlock.height, newBlock.header.hash)
                    return
                }
                if (splitPoint == null) {
                    // This should absolutely never happen
                    // (lets not write the full block to disk to keep any bugs which allow this to happen
                    //  from writing unreasonable amounts of data to disk)
                    throw VerificationException("Block forks the chain but splitPoint is null")
                } else {
                    // We aren't actually spending any transactions (yet) because we are on a fork
                    addToBlockStore(storedPrev, block)
                    val splitPointHeight = splitPoint.height
                    val splitPointHash = splitPoint.header.hashAsString
                    log.info("Block forks the chain at height {}/block {}, but it did not cause a reorganize:\n{}",
                            splitPointHeight, splitPointHash, newBlock.header.hashAsString)
                }
            }

            // We may not have any transactions if we received only a header, which can happen during fast catchup.
            // If we do, send them to the wallet but state that they are on a side chain so it knows not to try and
            // spend them until they become activated.
            if (block.transactions != null || filtered) {
                informListenersForNewBlock(block, NewBlockType.SIDE_CHAIN, filteredTxHashList, filteredTxn, newBlock)
            }

            if (haveNewBestChain)
                handleNewBestChain(storedPrev, newBlock, block, expensiveChecks)
        }
    }

    @Throws(VerificationException::class)
    private fun informListenersForNewBlock(block: Block, newBlockType: NewBlockType,
                                           filteredTxHashList: List<Sha256Hash>?,
                                           filteredTxn: Map<Sha256Hash, Transaction>?,
                                           newStoredBlock: StoredBlock) {
        // Notify the listeners of the new block, so the depth and workDone of stored transactions can be updated
        // (in the case of the listener being a wallet). Wallets need to know how deep each transaction is so
        // coinbases aren't used before maturity.
        var first = true
        val falsePositives = Sets.newHashSet<Sha256Hash>()
        if (filteredTxHashList != null) falsePositives.addAll(filteredTxHashList)

        for (registration in transactionReceivedListeners) {
            if (registration.executor === Threading.SAME_THREAD) {
                informListenerForNewTransactions(block, newBlockType, filteredTxHashList, filteredTxn,
                        newStoredBlock, first, registration.listener, falsePositives)
            } else {
                // Listener wants to be run on some other thread, so marshal it across here.
                val notFirst = !first
                registration.executor.execute {
                    try {
                        // We can't do false-positive handling when executing on another thread
                        val ignoredFalsePositives = Sets.newHashSet<Sha256Hash>()
                        informListenerForNewTransactions(block, newBlockType, filteredTxHashList, filteredTxn,
                                newStoredBlock, notFirst, registration.listener, ignoredFalsePositives)
                    } catch (e: VerificationException) {
                        log.error("Block chain listener threw exception: ", e)
                        // Don't attempt to relay this back to the original peer thread if this was an async
                        // listener invocation.
                        // TODO: Make exception reporting a global feature and use it here.
                    }
                }
            }
            first = false
        }

        for (registration in newBestBlockListeners) {
            if (registration.executor === Threading.SAME_THREAD) {
                if (newBlockType == NewBlockType.BEST_CHAIN)
                    registration.listener.notifyNewBestBlock(newStoredBlock)
            } else {
                // Listener wants to be run on some other thread, so marshal it across here.
                registration.executor.execute {
                    try {
                        if (newBlockType == NewBlockType.BEST_CHAIN)
                            registration.listener.notifyNewBestBlock(newStoredBlock)
                    } catch (e: VerificationException) {
                        log.error("Block chain listener threw exception: ", e)
                        // Don't attempt to relay this back to the original peer thread if this was an async
                        // listener invocation.
                        // TODO: Make exception reporting a global feature and use it here.
                    }
                }
            }
            first = false
        }

        trackFalsePositives(falsePositives.size)
    }

    /**
     * Disconnect each transaction in the block (after reading it from the block store)
     * Only called if(shouldVerifyTransactions())
     * @throws PrunedException if block does not exist as a [StoredUndoableBlock] in the block store.
     * @throws BlockStoreException if the block store had an underlying error or block does not exist in the block store at all.
     */
    @Throws(PrunedException::class, BlockStoreException::class)
    protected abstract fun disconnectTransactions(block: StoredBlock)

    /**
     * Called as part of connecting a block when the new block results in a different chain having higher total work.
     *
     * if (shouldVerifyTransactions)
     * Either newChainHead needs to be in the block store as a FullStoredBlock, or (block != null && block.transactions != null)
     */
    @Throws(BlockStoreException::class, VerificationException::class, PrunedException::class)
    private fun handleNewBestChain(storedPrev: StoredBlock, newChainHead: StoredBlock, block: Block?, expensiveChecks: Boolean) {
        checkState(lock.isHeldByCurrentThread)
        // This chain has overtaken the one we currently believe is best. Reorganize is required.
        //
        // Firstly, calculate the block at which the chain diverged. We only need to examine the
        // chain from beyond this block to find differences.
        val head = chainHead
        val splitPoint = findSplit(newChainHead, head, blockStore)
        log.info("Re-organize after split at height {}", splitPoint.height)
        log.info("Old chain head: {}", head.header.hashAsString)
        log.info("New chain head: {}", newChainHead.header.hashAsString)
        log.info("Split at block: {}", splitPoint.header.hashAsString)
        // Then build a list of all blocks in the old part of the chain and the new part.
        val oldBlocks = getPartialChain(head, splitPoint, blockStore)
        val newBlocks = getPartialChain(newChainHead, splitPoint, blockStore)
        // Disconnect each transaction in the previous main chain that is no longer in the new main chain
        var storedNewHead = splitPoint
        if (shouldVerifyTransactions()) {
            for (oldBlock in oldBlocks) {
                try {
                    disconnectTransactions(oldBlock)
                } catch (e: PrunedException) {
                    // We threw away the data we need to re-org this deep! We need to go back to a peer with full
                    // block contents and ask them for the relevant data then rebuild the indexs. Or we could just
                    // give up and ask the human operator to help get us unstuck (eg, rescan from the genesis block).
                    // TODO: Retry adding this block when we get a block with hash e.hash
                    throw e
                }

            }
            var cursor: StoredBlock
            // Walk in ascending chronological order.
            val it = newBlocks.descendingIterator()
            while (it.hasNext()) {
                cursor = it.next()
                val cursorBlock = cursor.header
                if (expensiveChecks && cursorBlock.timeSeconds <= getMedianTimestampOfRecentBlocks(cursor.getPrev(blockStore), blockStore))
                    throw VerificationException("Block's timestamp is too early during reorg")
                val txOutChanges: TransactionOutputChanges
                if (cursor !== newChainHead || block == null)
                    txOutChanges = connectTransactions(cursor)
                else
                    txOutChanges = connectTransactions(newChainHead.height, block)
                storedNewHead = addToBlockStore(storedNewHead, cursorBlock.cloneAsHeader(), txOutChanges)
            }
        } else {
            // (Finally) write block to block store
            storedNewHead = addToBlockStore(storedPrev, newChainHead.header)
        }
        // Now inform the listeners. This is necessary so the set of currently active transactions (that we can spend)
        // can be updated to take into account the re-organize. We might also have received new coins we didn't have
        // before and our previous spends might have been undone.
        for (registration in reorganizeListeners) {
            if (registration.executor === Threading.SAME_THREAD) {
                // Short circuit the executor so we can propagate any exceptions.
                // TODO: Do we really need to do this or should it be irrelevant?
                registration.listener.reorganize(splitPoint, oldBlocks, newBlocks)
            } else {
                registration.executor.execute {
                    try {
                        registration.listener.reorganize(splitPoint, oldBlocks, newBlocks)
                    } catch (e: VerificationException) {
                        log.error("Block chain listener threw exception during reorg", e)
                    }
                }
            }
        }
        // Update the pointer to the best known block.
        chainHead = storedNewHead
    }

    enum class NewBlockType {
        BEST_CHAIN,
        SIDE_CHAIN
    }



    /**
     * For each block in orphanBlocks, see if we can now fit it on top of the chain and if so, do so.
     */
    @Throws(VerificationException::class, BlockStoreException::class, PrunedException::class)
    private fun tryConnectingOrphans() {
        checkState(lock.isHeldByCurrentThread)
        // For each block in our orphan list, try and fit it onto the head of the chain. If we succeed remove it
        // from the list and keep going. If we changed the head of the list at the end of the round try again until
        // we can't fit anything else on the top.
        //
        // This algorithm is kind of crappy, we should do a topo-sort then just connect them in order, but for small
        // numbers of orphan blocks it does OK.
        var blocksConnectedThisRound: Int
        do {
            blocksConnectedThisRound = 0
            val iter = orphanBlocks.values.iterator()
            while (iter.hasNext()) {
                val orphanBlock = iter.next()
                // Look up the blocks previous.
                val prev = getStoredBlockInCurrentScope(orphanBlock.block.getPrevBlockHash())
                if (prev == null) {
                    // This is still an unconnected/orphan block.
                    log.debug("Orphan block {} is not connectable right now", orphanBlock.block.hash)
                    continue
                }
                // Otherwise we can connect it now.
                // False here ensures we don't recurse infinitely downwards when connecting huge chains.
                log.info("Connected orphan {}", orphanBlock.block.hash)
                add(orphanBlock.block, false, orphanBlock.filteredTxHashes, orphanBlock.filteredTxn)
                iter.remove()
                blocksConnectedThisRound++
            }
            if (blocksConnectedThisRound > 0) {
                log.info("Connected {} orphan blocks.", blocksConnectedThisRound)
            }
        } while (blocksConnectedThisRound > 0)
    }



    /**
     * An orphan block is one that does not connect to the chain anywhere (ie we can't find its parent, therefore
     * it's an orphan). Typically this occurs when we are downloading the chain and didn't reach the head yet, and/or
     * if a block is solved whilst we are downloading. It's possible that we see a small amount of orphan blocks which
     * chain together, this method tries walking backwards through the known orphan blocks to find the bottom-most.
     *
     * @return from or one of froms parents, or null if "from" does not identify an orphan block
     */
    fun getOrphanRoot(from: Sha256Hash): Block? {
        lock.lock()
        try {
            var cursor: OrphanBlock? = orphanBlocks.get(from) ?: return null
            var tmp: OrphanBlock? = null
            while ( { tmp = orphanBlocks.get(cursor?.block?.getPrevBlockHash()); tmp }() != null) {
                cursor = tmp
            }
            return cursor!!.block
        } finally {
            lock.unlock()
        }
    }

    /** Returns true if the given block is currently in the orphan blocks list.  */
    fun isOrphan(block: Sha256Hash): Boolean {
        lock.lock()
        try {
            return orphanBlocks.containsKey(block)
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns an estimate of when the given block will be reached, assuming a perfect 10 minute average for each
     * block. This is useful for turning transaction lock times into human readable times. Note that a height in
     * the past will still be estimated, even though the time of solving is actually known (we won't scan backwards
     * through the chain to obtain the right answer).
     */
    fun estimateBlockTime(height: Int): Date {
        synchronized(chainHeadLock) {
            val offset = (height - chainHead.height).toLong()
            val headTime = chainHead.header.timeSeconds
            val estimated = headTime * 1000 + 1000L * 60L * 10L * offset
            return Date(estimated)
        }
    }

    /**
     * Returns a future that completes when the block chain has reached the given height. Yields the
     * [StoredBlock] of the block that reaches that height first. The future completes on a peer thread.
     */
    fun getHeightFuture(height: Int): ListenableFuture<StoredBlock> {
        val result = SettableFuture.create<StoredBlock>()
        addNewBestBlockListener(Threading.SAME_THREAD, object : NewBestBlockListener {
            @Throws(VerificationException::class)
            override fun notifyNewBestBlock(block: StoredBlock) {
                if (block.height >= height) {
                    removeNewBestBlockListener(this)
                    result.set(block)
                }
            }
        })
        return result
    }

    /*
     * We completed handling of a filtered block. Update false-positive estimate based
     * on the total number of transactions in the original block.
     *
     * count includes filtered transactions, transactions that were passed in and were relevant
     * and transactions that were false positives (i.e. includes all transactions in the block).
     */
    fun trackFilteredTransactions(count: Int) {
        // Track non-false-positives in batch.  Each non-false-positive counts as
        // 0.0 towards the estimate.
        //
        // This is slightly off because we are applying false positive tracking before non-FP tracking,
        // which counts FP as if they came at the beginning of the block.  Assuming uniform FP
        // spread in a block, this will somewhat underestimate the FP rate (5% for 1000 tx block).
        val alphaDecay = Math.pow(1 - FP_ESTIMATOR_ALPHA, count.toDouble())

        // new_rate = alpha_decay * new_rate
        falsePositiveRate = alphaDecay * falsePositiveRate

        val betaDecay = Math.pow(1 - FP_ESTIMATOR_BETA, count.toDouble())

        // trend = beta * (new_rate - old_rate) + beta_decay * trend
        falsePositiveTrend = FP_ESTIMATOR_BETA * count.toDouble() * (falsePositiveRate - previousFalsePositiveRate) + betaDecay * falsePositiveTrend

        // new_rate += alpha_decay * trend
        falsePositiveRate += alphaDecay * falsePositiveTrend

        // Stash new_rate in old_rate
        previousFalsePositiveRate = falsePositiveRate
    }

    /* Irrelevant transactions were received.  Update false-positive estimate. */
    internal fun trackFalsePositives(count: Int) {
        // Track false positives in batch by adding alpha to the false positive estimate once per count.
        // Each false positive counts as 1.0 towards the estimate.
        falsePositiveRate += FP_ESTIMATOR_ALPHA * count
        if (count > 0)
            log.debug("{} false positives, current rate = {} trend = {}", count, falsePositiveRate, falsePositiveTrend)
    }

    /** Resets estimates of false positives. Used when the filter is sent to the peer.  */
    fun resetFalsePositiveEstimate() {
        falsePositiveRate = 0.0
        falsePositiveTrend = 0.0
        previousFalsePositiveRate = 0.0
    }

    companion object {
        private val log = LoggerFactory.getLogger(AbstractBlockChain::class.java!!)

        /** False positive estimation uses a double exponential moving average.  */
        val FP_ESTIMATOR_ALPHA = 0.0001
        /** False positive estimation uses a double exponential moving average.  */
        val FP_ESTIMATOR_BETA = 0.01

        @Throws(VerificationException::class)
        private fun informListenerForNewTransactions(block: Block, newBlockType: NewBlockType,
                                                     filteredTxHashList: List<Sha256Hash>?,
                                                     filteredTxn: Map<Sha256Hash, Transaction>?,
                                                     newStoredBlock: StoredBlock, first: Boolean,
                                                     listener: TransactionReceivedInBlockListener,
                                                     falsePositives: MutableSet<Sha256Hash>) {
            if (block.transactions != null) {
                // If this is not the first wallet, ask for the transactions to be duplicated before being given
                // to the wallet when relevant. This ensures that if we have two connected wallets and a tx that
                // is relevant to both of them, they don't end up accidentally sharing the same object (which can
                // result in temporary in-memory corruption during re-orgs). See bug 257. We only duplicate in
                // the case of multiple wallets to avoid an unnecessary efficiency hit in the common case.
                sendTransactionsToListener(newStoredBlock, newBlockType, listener, 0, block.transactions!!,
                        !first, falsePositives)
            } else if (filteredTxHashList != null) {
                checkNotNull<Map<Sha256Hash, Transaction>>(filteredTxn)
                // We must send transactions to listeners in the order they appeared in the block - thus we iterate over the
                // set of hashes and call sendTransactionsToListener with individual txn when they have not already been
                // seen in loose broadcasts - otherwise notifyTransactionIsInBlock on the hash.
                var relativityOffset = 0
                for (hash in filteredTxHashList) {
                    val tx = filteredTxn!![hash]
                    if (tx != null) {
                        sendTransactionsToListener(newStoredBlock, newBlockType, listener, relativityOffset,
                                listOf<Transaction>(tx), !first, falsePositives)
                    } else {
                        if (listener.notifyTransactionIsInBlock(hash, newStoredBlock, newBlockType, relativityOffset)) {
                            falsePositives.remove(hash)
                        }
                    }
                    relativityOffset++
                }
            }
        }

        /**
         * Gets the median timestamp of the last 11 blocks
         */
        @Throws(BlockStoreException::class)
        fun getMedianTimestampOfRecentBlocks(storedBlock: StoredBlock, store: BlockStore): Long {


            val timestamps = LongArray(11)
            var unused = 9
            timestamps[10] = storedBlock.header.timeSeconds
            var prevBlock: StoredBlock? = storedBlock.getPrev(store)

            while (unused >= 0 && prevBlock != null) {
                timestamps[unused--] = prevBlock.header.timeSeconds
                prevBlock = prevBlock.getPrev(store)
            }

            Arrays.sort(timestamps, unused + 1, 11)
            return timestamps[unused + (11 - unused) / 2]
        }

        /**
         * Returns the set of contiguous blocks between 'higher' and 'lower'. Higher is included, lower is not.
         */
        @Throws(BlockStoreException::class)
        private fun getPartialChain(higher: StoredBlock, lower: StoredBlock, store: BlockStore): LinkedList<StoredBlock> {
            checkArgument(higher.height > lower.height, "higher and lower are reversed")
            val results = LinkedList<StoredBlock>()
            var cursor = higher
            while (true) {
                results.add(cursor)
                cursor = checkNotNull(cursor.getPrev(store), "Ran off the end of the chain")
                if (cursor == lower) break
            }
            return results
        }

        /**
         * Locates the point in the chain at which newStoredBlock and chainHead diverge. Returns null if no split point was
         * found (ie they are not part of the same chain). Returns newChainHead or chainHead if they don't actually diverge
         * but are part of the same chain.
         */
        @Throws(BlockStoreException::class)
        private fun findSplit(newChainHead: StoredBlock, oldChainHead: StoredBlock,
                              store: BlockStore): StoredBlock {
            var currentChainCursor = oldChainHead
            var newChainCursor = newChainHead
            // Loop until we find the block both chains have in common. Example:
            //
            //    A -> B -> C -> D
            //         \--> E -> F -> G
            //
            // findSplit will return block B. oldChainHead = D and newChainHead = G.
            while (currentChainCursor != newChainCursor) {
                if (currentChainCursor.height > newChainCursor.height) {
                    currentChainCursor = currentChainCursor.getPrev(store)
                    checkNotNull(currentChainCursor, "Attempt to follow an orphan chain")
                } else {
                    newChainCursor = newChainCursor.getPrev(store)
                    checkNotNull(newChainCursor, "Attempt to follow an orphan chain")
                }
            }
            return currentChainCursor
        }

        @Throws(VerificationException::class)
        private fun sendTransactionsToListener(block: StoredBlock, blockType: NewBlockType,
                                               listener: TransactionReceivedInBlockListener,
                                               relativityOffset: Int,
                                               transactions: List<Transaction>,
                                               clone: Boolean,
                                               falsePositives: MutableSet<Sha256Hash>) {
            var relativityOffset = relativityOffset
            for (tx in transactions) {
                try {
                    falsePositives.remove(tx.hash)
                    if (clone) {
                        val tx1= tx.params!!.defaultSerializer!!.makeTransaction(tx.bitcoinSerialize())
                        listener.receiveFromBlock(tx1, block, blockType, relativityOffset++)
                    }else{
                        listener.receiveFromBlock(tx, block, blockType, relativityOffset++)
                    }

                } catch (e: ScriptException) {
                    // We don't want scripts we don't understand to break the block chain so just note that this tx was
                    // not scanned here and continue.
                    log.warn("Failed to parse a script: " + e.toString())
                } catch (e: ProtocolException) {
                    // Failed to duplicate tx, should never happen.
                    throw RuntimeException(e)
                }

            }
        }
    }
}
