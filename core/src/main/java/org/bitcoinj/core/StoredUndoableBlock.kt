/*
 * Copyright 2011 Google Inc.
 * Copyright 2012 Matt Corallo.
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

/**
 * Contains minimal data neccessary to disconnect/connect the transactions
 * in the stored block at will. Can either store the full set of
 * transactions (if the inputs for the block have not been tested to work)
 * or the set of transaction outputs created/destroyed when the block is
 * connected.
 */
class StoredUndoableBlock {

    /**
     * Get the hash of the represented block
     */
    var hash: Sha256Hash
        internal set

    // Only one of either txOutChanges or transactions will be set
    /**
     * Get the transaction output changes if they have been calculated, otherwise null.
     * Only one of this and getTransactions() will return a non-null value.
     */
    var txOutChanges: TransactionOutputChanges? = null
        private set
    /**
     * Get the full list of transactions if it is stored, otherwise null.
     * Only one of this and getTxOutChanges() will return a non-null value.
     */
    var transactions: List<Transaction>? = null
        private set

    constructor(hash: Sha256Hash, txOutChanges: TransactionOutputChanges) {
        this.hash = hash
        this.transactions = null
        this.txOutChanges = txOutChanges
    }

    constructor(hash: Sha256Hash, transactions: List<Transaction>) {
        this.hash = hash
        this.txOutChanges = null
        this.transactions = transactions
    }

    override fun hashCode(): Int {
        return hash.hashCode()
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        return if (o == null || javaClass != o.javaClass) false else hash == (o as StoredUndoableBlock).hash
    }

    override fun toString(): String {
        return "Undoable Block " + hash
    }
}
