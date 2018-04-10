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

import com.google.common.base.Preconditions.checkArgument

import org.bitcoinj.store.BlockStore
import org.bitcoinj.store.BlockStoreException
import org.bitcoinj.wallet.Wallet

import java.util.ArrayList

// TODO: Rename this class to SPVBlockChain at some point.

/**
 * A BlockChain implements the *simplified payment verification* mode of the Bitcoin protocol. It is the right
 * choice to use for programs that have limited resources as it won't verify transactions signatures or attempt to store
 * all of the block chain. Really, this class should be called SPVBlockChain but for backwards compatibility it is not.
 */
class BlockChain
/**
 * Constructs a BlockChain connected to the given list of listeners and a store.
 */
@Throws(BlockStoreException::class)
constructor(params: Context, wallets: List<Wallet>,
            /** Keeps a map of block hashes to StoredBlocks.  */
            protected val blockStore: BlockStore) : AbstractBlockChain(params, wallets, blockStore) {

    /**
     *
     * Constructs a BlockChain connected to the given wallet and store. To obtain a [Wallet] you can construct
     * one from scratch, or you can deserialize a saved wallet from disk using
     * [Wallet.loadFromFile]
     *
     *
     * For the store, you should use [org.bitcoinj.store.SPVBlockStore] or you could also try a
     * [org.bitcoinj.store.MemoryBlockStore] if you want to hold all headers in RAM and don't care about
     * disk serialization (this is rare).
     */
    @Throws(BlockStoreException::class)
    constructor(context: Context, wallet: Wallet, blockStore: BlockStore) : this(context, ArrayList<Wallet>(), blockStore) {
        addWallet(wallet)
    }

    /** See [.BlockChain]}  */
    @Throws(BlockStoreException::class)
    constructor(params: NetworkParameters, wallet: Wallet, blockStore: BlockStore) : this(Context.getOrCreate(params), wallet, blockStore) {
    }

    /**
     * Constructs a BlockChain that has no wallet at all. This is helpful when you don't actually care about sending
     * and receiving coins but rather, just want to explore the network data structures.
     */
    @Throws(BlockStoreException::class)
    constructor(context: Context, blockStore: BlockStore) : this(context, ArrayList<Wallet>(), blockStore) {
    }

    /** See [.BlockChain]  */
    @Throws(BlockStoreException::class)
    constructor(params: NetworkParameters, blockStore: BlockStore) : this(params, ArrayList<Wallet>(), blockStore) {
    }

    /** See [.BlockChain]  */
    @Throws(BlockStoreException::class)
    constructor(params: NetworkParameters, wallets: List<Wallet>, blockStore: BlockStore) : this(Context.getOrCreate(params), wallets, blockStore) {
    }

    @Throws(BlockStoreException::class, VerificationException::class)
    override fun addToBlockStore(storedPrev: StoredBlock, blockHeader: Block, txOutChanges: TransactionOutputChanges?): StoredBlock {
        val newBlock = storedPrev.build(blockHeader)
        blockStore.put(newBlock)
        return newBlock
    }

    @Throws(BlockStoreException::class, VerificationException::class)
    override fun addToBlockStore(storedPrev: StoredBlock, blockHeader: Block): StoredBlock {
        val newBlock = storedPrev.build(blockHeader)
        blockStore.put(newBlock)
        return newBlock
    }

    @Throws(BlockStoreException::class)
    override fun rollbackBlockStore(height: Int) {
        lock.lock()
        try {
            val currentHeight = bestChainHeight
            checkArgument(height >= 0 && height <= currentHeight, "Bad height: %s", height)
            if (height == currentHeight)
                return  // nothing to do

            // Look for the block we want to be the new chain head
            var newChainHead: StoredBlock? = blockStore.chainHead
            while (newChainHead!!.height > height) {
                newChainHead = newChainHead.getPrev(blockStore)
                if (newChainHead == null)
                    throw BlockStoreException("Unreachable height")
            }

            // Modify store directly
            blockStore.put(newChainHead)
            this.setChainHead(newChainHead)
        } finally {
            lock.unlock()
        }
    }

    override fun shouldVerifyTransactions(): Boolean {
        return false
    }

    override fun connectTransactions(height: Int, block: Block): TransactionOutputChanges {
        // Don't have to do anything as this is only called if(shouldVerifyTransactions())
        throw UnsupportedOperationException()
    }

    override fun connectTransactions(newBlock: StoredBlock): TransactionOutputChanges {
        // Don't have to do anything as this is only called if(shouldVerifyTransactions())
        throw UnsupportedOperationException()
    }

    override fun disconnectTransactions(block: StoredBlock) {
        // Don't have to do anything as this is only called if(shouldVerifyTransactions())
        throw UnsupportedOperationException()
    }

    @Throws(BlockStoreException::class)
    override fun doSetChainHead(chainHead: StoredBlock) {
        blockStore.chainHead = chainHead
    }

    @Throws(BlockStoreException::class)
    override fun notSettingChainHead() {
        // We don't use DB transactions here, so we don't need to do anything
    }

    @Throws(BlockStoreException::class)
    override fun getStoredBlockInCurrentScope(hash: Sha256Hash?): StoredBlock? {
        return blockStore.get(hash)
    }

    @Throws(VerificationException::class, PrunedException::class)
    override fun add(block: FilteredBlock): Boolean {
        val success = super.add(block)
        if (success) {
            trackFilteredTransactions(block.transactionCount)
        }
        return success
    }
}
