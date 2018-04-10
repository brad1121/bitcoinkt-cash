/*
 * Copyright 2012 Matt Corallo.
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

import org.bitcoinj.script.Script
import org.bitcoinj.script.Script.VerifyFlag
import org.bitcoinj.store.BlockStoreException
import org.bitcoinj.store.FullPrunedBlockStore
import org.bitcoinj.utils.*
import org.bitcoinj.wallet.Wallet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.ArrayList
import java.util.LinkedList
import java.util.concurrent.*

import com.google.common.base.Preconditions.checkState

/**
 *
 * A FullPrunedBlockChain works in conjunction with a [FullPrunedBlockStore] to verify all the rules of the
 * Bitcoin system, with the downside being a large cost in system resources. Fully verifying means all unspent
 * transaction outputs are stored. Once a transaction output is spent and that spend is buried deep enough, the data
 * related to it is deleted to ensure disk space usage doesn't grow forever. For this reason a pruning node cannot
 * serve the full block chain to other clients, but it nevertheless provides the same security guarantees as Bitcoin
 * Core does.
 */
class FullPrunedBlockChain
/**
 * Constructs a block chain connected to the given list of wallets and a store.
 */
@Throws(BlockStoreException::class)
constructor(context: Context, listeners: List<Wallet>,
            /**
             * Keeps a map of block hashes to StoredBlocks.
             */
            protected val blockStore: FullPrunedBlockStore) : AbstractBlockChain(context, listeners, blockStore) {

    // Whether or not to execute scriptPubKeys before accepting a transaction (i.e. check signatures).
    private var runScripts = true

    // TODO: Remove lots of duplicated code in the two connectTransactions

    // TODO: execute in order of largest transaction (by input count) first
    internal var scriptVerificationExecutor = Executors.newFixedThreadPool(
            Runtime.getRuntime().availableProcessors(), ContextPropagatingThreadFactory("Script verification"))

    /**
     * Constructs a block chain connected to the given wallet and store. To obtain a [Wallet] you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using
     * [Wallet.loadFromFile]
     */
    @Throws(BlockStoreException::class)
    constructor(context: Context, wallet: Wallet, blockStore: FullPrunedBlockStore) : this(context, ArrayList<Wallet>(), blockStore) {
        addWallet(wallet)
    }

    /**
     * Constructs a block chain connected to the given wallet and store. To obtain a [Wallet] you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using
     * [Wallet.loadFromFile]
     */
    @Throws(BlockStoreException::class)
    constructor(params: NetworkParameters, wallet: Wallet, blockStore: FullPrunedBlockStore) : this(Context.getOrCreate(params), wallet, blockStore) {
    }

    /**
     * Constructs a block chain connected to the given store.
     */
    @Throws(BlockStoreException::class)
    constructor(context: Context, blockStore: FullPrunedBlockStore) : this(context, ArrayList<Wallet>(), blockStore) {
    }

    /**
     * See [.FullPrunedBlockChain]
     */
    @Throws(BlockStoreException::class)
    constructor(params: NetworkParameters, blockStore: FullPrunedBlockStore) : this(Context.getOrCreate(params), blockStore) {
    }

    init {
        // Ignore upgrading for now
        this.chainHead = blockStore.verifiedChainHead
    }

    /**
     * See [.FullPrunedBlockChain]
     */
    @Throws(BlockStoreException::class)
    constructor(params: NetworkParameters, listeners: List<Wallet>,
                blockStore: FullPrunedBlockStore) : this(Context.getOrCreate(params), listeners, blockStore) {
    }

    @Throws(BlockStoreException::class, VerificationException::class)
    override fun addToBlockStore(storedPrev: StoredBlock, header: Block, txOutChanges: TransactionOutputChanges?): StoredBlock {
        val newBlock = storedPrev.build(header)
        blockStore.put(newBlock, StoredUndoableBlock(newBlock.header.hash, txOutChanges))
        return newBlock
    }

    @Throws(BlockStoreException::class, VerificationException::class)
    override fun addToBlockStore(storedPrev: StoredBlock, block: Block): StoredBlock {
        val newBlock = storedPrev.build(block)
        blockStore.put(newBlock, StoredUndoableBlock(newBlock.header.hash, block.transactions))
        return newBlock
    }

    @Throws(BlockStoreException::class)
    override fun rollbackBlockStore(height: Int) {
        throw BlockStoreException("Unsupported")
    }

    override fun shouldVerifyTransactions(): Boolean {
        return true
    }

    /**
     * Whether or not to run scripts whilst accepting blocks (i.e. checking signatures, for most transactions).
     * If you're accepting data from an untrusted node, such as one found via the P2P network, this should be set
     * to true (which is the default). If you're downloading a chain from a node you control, script execution
     * is redundant because you know the connected node won't relay bad data to you. In that case it's safe to set
     * this to false and obtain a significant speedup.
     */
    fun setRunScripts(value: Boolean) {
        this.runScripts = value
    }

    /**
     * A job submitted to the executor which verifies signatures.
     */
    private class Verifier(internal val tx: Transaction, internal val prevOutScripts: List<Script>, internal val verifyFlags: Set<VerifyFlag>) : Callable<VerificationException> {

        @Throws(Exception::class)
        override fun call(): VerificationException? {
            try {
                val prevOutIt = prevOutScripts.listIterator()
                for (index in 0 until tx.inputs.size) {
                    val value = if (tx.getInput(index.toLong()).connectedOutput != null) tx.getInput(index.toLong()).connectedOutput!!.value else Coin.ZERO
                    tx.inputs[index].scriptSig.correctlySpends(tx, index.toLong(), prevOutIt.next(), value, verifyFlags)
                }
            } catch (e: VerificationException) {
                return e
            }

            return null
        }
    }

    /**
     * Get the [Script] from the script bytes or return Script of empty byte array.
     */
    private fun getScript(scriptBytes: ByteArray?): Script {
        try {
            return Script(scriptBytes)
        } catch (e: Exception) {
            return Script(ByteArray(0))
        }

    }

    /**
     * Get the address from the [Script] if it exists otherwise return empty string "".
     *
     * @param script The script.
     * @return The address.
     */
    private fun getScriptAddress(script: Script?): String {
        var address = ""
        try {
            if (script != null) {
                address = script.getToAddress(params, true).toString()
            }
        } catch (e: Exception) {
        }

        return address
    }

    @Throws(VerificationException::class, BlockStoreException::class)
    override fun connectTransactions(height: Int, block: Block): TransactionOutputChanges {
        checkState(lock.isHeldByCurrentThread)
        if (block.transactions == null)
            throw RuntimeException("connectTransactions called with Block that didn't have transactions!")
        if (!params.passesCheckpoint(height, block.hash))
            throw VerificationException("Block failed checkpoint lockin at " + height)

        blockStore.beginDatabaseBatchWrite()

        val txOutsSpent = LinkedList<UTXO>()
        val txOutsCreated = LinkedList<UTXO>()
        var sigOps: Long = 0

        if (scriptVerificationExecutor.isShutdown)
            scriptVerificationExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors())

        val listScriptVerificationResults = ArrayList<Future<VerificationException>>(block.transactions!!.size)
        try {
            if (!params.isCheckpoint(height)) {
                // BIP30 violator blocks are ones that contain a duplicated transaction. They are all in the
                // checkpoints list and we therefore only check non-checkpoints for duplicated transactions here. See the
                // BIP30 document for more details on this: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
                for (tx in block.transactions!!) {
                    val verifyFlags = params.getTransactionVerificationFlags(block, tx, versionTally, height)
                    val hash = tx.hash
                    // If we already have unspent outputs for this hash, we saw the tx already. Either the block is
                    // being added twice (bug) or the block is a BIP30 violator.
                    if (blockStore.hasUnspentOutputs(hash, tx.outputs.size))
                        throw VerificationException("Block failed BIP30 test!")
                    if (verifyFlags.contains(VerifyFlag.P2SH))
                    // We already check non-BIP16 sigops in Block.verifyTransactions(true)
                        sigOps += tx.sigOpCount.toLong()
                }
            }
            var totalFees = Coin.ZERO
            var coinbaseValue: Coin? = null
            for (tx in block.transactions!!) {
                val isCoinBase = tx.isCoinBase
                var valueIn = Coin.ZERO
                var valueOut = Coin.ZERO
                val prevOutScripts = LinkedList<Script>()
                val verifyFlags = params.getTransactionVerificationFlags(block, tx, versionTally, height)
                if (!isCoinBase) {
                    // For each input of the transaction remove the corresponding output from the set of unspent
                    // outputs.
                    for (index in 0 until tx.inputs.size) {
                        val `in` = tx.inputs[index]
                        val prevOut = blockStore.getTransactionOutput(`in`.outpoint!!.hash,
                                `in`.outpoint!!.index) ?: throw VerificationException("Attempted to spend a non-existent or already spent output!")
// Coinbases can't be spent until they mature, to avoid re-orgs destroying entire transaction
                        // chains. The assumption is there will ~never be re-orgs deeper than the spendable coinbase
                        // chain depth.
                        if (prevOut.isCoinbase) {
                            if (height - prevOut.height < params.spendableCoinbaseDepth) {
                                throw VerificationException("Tried to spend coinbase at depth " + (height - prevOut.height))
                            }
                        }
                        // TODO: Check we're not spending the genesis transaction here. Bitcoin Core won't allow it.
                        valueIn = valueIn.add(prevOut.value!!)
                        if (verifyFlags.contains(VerifyFlag.P2SH)) {
                            if (prevOut.script!!.isPayToScriptHash)
                                sigOps += Script.getP2SHSigOpCount(`in`.scriptBytes)
                            if (sigOps > Block.MAX_BLOCK_SIGOPS)
                                throw VerificationException("Too many P2SH SigOps in block")
                        }

                        prevOutScripts.add(prevOut.script)
                        blockStore.removeUnspentTransactionOutput(prevOut)
                        txOutsSpent.add(prevOut)
                    }
                }
                val hash = tx.hash
                for (out in tx.outputs) {
                    valueOut = valueOut.add(out.value)
                    // For each output, add it to the set of unspent outputs so it can be consumed in future.
                    val script = getScript(out.scriptBytes)
                    val newOut = UTXO(hash,
                            out.index.toLong(),
                            out.value,
                            height, isCoinBase,
                            script,
                            getScriptAddress(script))
                    blockStore.addUnspentTransactionOutput(newOut)
                    txOutsCreated.add(newOut)
                }
                // All values were already checked for being non-negative (as it is verified in Transaction.verify())
                // but we check again here just for defence in depth. Transactions with zero output value are OK.
                if (valueOut.signum() < 0 || valueOut.compareTo(params.maxMoney) > 0)
                    throw VerificationException("Transaction output value out of range")
                if (isCoinBase) {
                    coinbaseValue = valueOut
                } else {
                    if (valueIn.compareTo(valueOut) < 0 || valueIn.compareTo(params.maxMoney) > 0)
                        throw VerificationException("Transaction input value out of range")
                    totalFees = totalFees.add(valueIn.subtract(valueOut))
                }

                if (!isCoinBase && runScripts) {
                    // Because correctlySpends modifies transactions, this must come after we are done with tx
                    val future = FutureTask(Verifier(tx, prevOutScripts, verifyFlags))
                    scriptVerificationExecutor.execute(future)
                    listScriptVerificationResults.add(future)
                }
            }
            if (totalFees.compareTo(params.maxMoney) > 0 || block.getBlockInflation(height).add(totalFees).compareTo(coinbaseValue!!) < 0)
                throw VerificationException("Transaction fees out of range")
            for (future in listScriptVerificationResults) {
                val e: VerificationException?
                try {
                    e = future.get()
                } catch (thrownE: InterruptedException) {
                    throw RuntimeException(thrownE) // Shouldn't happen
                } catch (thrownE: ExecutionException) {
                    log.error("Script.correctlySpends threw a non-normal exception: " + thrownE.cause)
                    throw VerificationException("Bug in Script.correctlySpends, likely script malformed in some new and interesting way.", thrownE)
                }

                if (e != null)
                    throw e
            }
        } catch (e: VerificationException) {
            scriptVerificationExecutor.shutdownNow()
            blockStore.abortDatabaseBatchWrite()
            throw e
        } catch (e: BlockStoreException) {
            scriptVerificationExecutor.shutdownNow()
            blockStore.abortDatabaseBatchWrite()
            throw e
        }

        return TransactionOutputChanges(txOutsCreated, txOutsSpent)
    }

    @Synchronized
    @Throws(VerificationException::class, BlockStoreException::class, PrunedException::class)
    override
            /**
             * Used during reorgs to connect a block previously on a fork
             */
    fun connectTransactions(newBlock: StoredBlock): TransactionOutputChanges {
        checkState(lock.isHeldByCurrentThread)
        if (!params.passesCheckpoint(newBlock.height, newBlock.header.hash))
            throw VerificationException("Block failed checkpoint lockin at " + newBlock.height)

        blockStore.beginDatabaseBatchWrite()
        val block = blockStore.getUndoBlock(newBlock.header.hash)
        if (block == null) {
            // We're trying to re-org too deep and the data needed has been deleted.
            blockStore.abortDatabaseBatchWrite()
            throw PrunedException(newBlock.header.hash)
        }
        val txOutChanges: TransactionOutputChanges?
        try {
            val transactions = block.transactions
            if (transactions != null) {
                val txOutsSpent = LinkedList<UTXO>()
                val txOutsCreated = LinkedList<UTXO>()
                var sigOps: Long = 0

                if (!params.isCheckpoint(newBlock.height)) {
                    for (tx in transactions) {
                        val hash = tx.hash
                        if (blockStore.hasUnspentOutputs(hash, tx.outputs.size))
                            throw VerificationException("Block failed BIP30 test!")
                    }
                }
                var totalFees = Coin.ZERO
                var coinbaseValue: Coin? = null

                if (scriptVerificationExecutor.isShutdown)
                    scriptVerificationExecutor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors())
                val listScriptVerificationResults = ArrayList<Future<VerificationException>>(transactions.size)
                for (tx in transactions) {
                    val verifyFlags = params.getTransactionVerificationFlags(newBlock.header, tx, versionTally, Integer.SIZE)
                    val isCoinBase = tx.isCoinBase
                    var valueIn = Coin.ZERO
                    var valueOut = Coin.ZERO
                    val prevOutScripts = LinkedList<Script>()

                    if (!isCoinBase) {
                        for (index in 0 until tx.inputs.size) {
                            val `in` = tx.inputs[index]
                            val prevOut = blockStore.getTransactionOutput(`in`.outpoint!!.hash,
                                    `in`.outpoint!!.index) ?: throw VerificationException("Attempted spend of a non-existent or already spent output!")
                            if (prevOut.isCoinbase && newBlock.height - prevOut.height < params.spendableCoinbaseDepth)
                                throw VerificationException("Tried to spend coinbase at depth " + (newBlock.height - prevOut.height))
                            valueIn = valueIn.add(prevOut.value!!)
                            if (verifyFlags.contains(VerifyFlag.P2SH)) {
                                if (prevOut.script!!.isPayToScriptHash)
                                    sigOps += Script.getP2SHSigOpCount(`in`.scriptBytes)
                                if (sigOps > Block.MAX_BLOCK_SIGOPS)
                                    throw VerificationException("Too many P2SH SigOps in block")
                            }

                            // TODO: Enforce DER signature format

                            prevOutScripts.add(prevOut.script)

                            blockStore.removeUnspentTransactionOutput(prevOut)
                            txOutsSpent.add(prevOut)
                        }
                    }
                    val hash = tx.hash
                    for (out in tx.outputs) {
                        valueOut = valueOut.add(out.value)
                        val script = getScript(out.scriptBytes)
                        val newOut = UTXO(hash,
                                out.index.toLong(),
                                out.value,
                                newBlock.height,
                                isCoinBase,
                                script,
                                getScriptAddress(script))
                        blockStore.addUnspentTransactionOutput(newOut)
                        txOutsCreated.add(newOut)
                    }
                    // All values were already checked for being non-negative (as it is verified in Transaction.verify())
                    // but we check again here just for defence in depth. Transactions with zero output value are OK.
                    if (valueOut.signum() < 0 || valueOut.compareTo(params.maxMoney) > 0)
                        throw VerificationException("Transaction output value out of range")
                    if (isCoinBase) {
                        coinbaseValue = valueOut
                    } else {
                        if (valueIn.compareTo(valueOut) < 0 || valueIn.compareTo(params.maxMoney) > 0)
                            throw VerificationException("Transaction input value out of range")
                        totalFees = totalFees.add(valueIn.subtract(valueOut))
                    }

                    if (!isCoinBase) {
                        // Because correctlySpends modifies transactions, this must come after we are done with tx
                        val future = FutureTask(Verifier(tx, prevOutScripts, verifyFlags))
                        scriptVerificationExecutor.execute(future)
                        listScriptVerificationResults.add(future)
                    }
                }
                if (totalFees.compareTo(params.maxMoney) > 0 || newBlock.header.getBlockInflation(newBlock.height).add(totalFees).compareTo(coinbaseValue!!) < 0)
                    throw VerificationException("Transaction fees out of range")
                txOutChanges = TransactionOutputChanges(txOutsCreated, txOutsSpent)
                for (future in listScriptVerificationResults) {
                    val e: VerificationException?
                    try {
                        e = future.get()
                    } catch (thrownE: InterruptedException) {
                        throw RuntimeException(thrownE) // Shouldn't happen
                    } catch (thrownE: ExecutionException) {
                        log.error("Script.correctlySpends threw a non-normal exception: " + thrownE.cause)
                        throw VerificationException("Bug in Script.correctlySpends, likely script malformed in some new and interesting way.", thrownE)
                    }

                    if (e != null)
                        throw e
                }
            } else {
                txOutChanges = block.txOutChanges
                if (!params.isCheckpoint(newBlock.height))
                    for (out in txOutChanges!!.txOutsCreated) {
                        val hash = out.hash
                        if (blockStore.getTransactionOutput(hash, out.index) != null)
                            throw VerificationException("Block failed BIP30 test!")
                    }
                for (out in txOutChanges!!.txOutsCreated)
                    blockStore.addUnspentTransactionOutput(out)
                for (out in txOutChanges.txOutsSpent)
                    blockStore.removeUnspentTransactionOutput(out)
            }
        } catch (e: VerificationException) {
            scriptVerificationExecutor.shutdownNow()
            blockStore.abortDatabaseBatchWrite()
            throw e
        } catch (e: BlockStoreException) {
            scriptVerificationExecutor.shutdownNow()
            blockStore.abortDatabaseBatchWrite()
            throw e
        }

        return txOutChanges
    }

    /**
     * This is broken for blocks that do not pass BIP30, so all BIP30-failing blocks which are allowed to fail BIP30
     * must be checkpointed.
     */
    @Throws(PrunedException::class, BlockStoreException::class)
    override fun disconnectTransactions(oldBlock: StoredBlock) {
        checkState(lock.isHeldByCurrentThread)
        blockStore.beginDatabaseBatchWrite()
        try {
            val undoBlock = blockStore.getUndoBlock(oldBlock.header.hash) ?: throw PrunedException(oldBlock.header.hash)
            val txOutChanges = undoBlock.txOutChanges
            for (out in txOutChanges!!.txOutsSpent)
                blockStore.addUnspentTransactionOutput(out)
            for (out in txOutChanges.txOutsCreated)
                blockStore.removeUnspentTransactionOutput(out)
        } catch (e: PrunedException) {
            blockStore.abortDatabaseBatchWrite()
            throw e
        } catch (e: BlockStoreException) {
            blockStore.abortDatabaseBatchWrite()
            throw e
        }

    }

    @Throws(BlockStoreException::class)
    override fun doSetChainHead(chainHead: StoredBlock) {
        checkState(lock.isHeldByCurrentThread)
        blockStore.verifiedChainHead = chainHead
        blockStore.commitDatabaseBatchWrite()
    }

    @Throws(BlockStoreException::class)
    override fun notSettingChainHead() {
        blockStore.abortDatabaseBatchWrite()
    }

    @Throws(BlockStoreException::class)
    override fun getStoredBlockInCurrentScope(hash: Sha256Hash?): StoredBlock? {
        checkState(lock.isHeldByCurrentThread)
        return blockStore.getOnceUndoableStoredBlock(hash)
    }

    companion object {
        private val log = LoggerFactory.getLogger(FullPrunedBlockChain::class.java!!)
    }
}
