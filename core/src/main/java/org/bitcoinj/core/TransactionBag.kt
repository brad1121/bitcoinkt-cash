/*
 * Copyright 2014 Giannis Dzegoutanis
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
import org.bitcoinj.wallet.WalletTransaction

/**
 * This interface is used to abstract the [org.bitcoinj.wallet.Wallet] and the [org.bitcoinj.core.Transaction]
 */
interface TransactionBag {
    /** Returns true if this wallet contains a public key which hashes to the given hash.  */
    fun isPubKeyHashMine(pubkeyHash: ByteArray): Boolean

    /** Returns true if this wallet is watching transactions for outputs with the script.  */
    fun isWatchedScript(script: Script): Boolean

    /** Returns true if this wallet contains a keypair with the given public key.  */
    fun isPubKeyMine(pubkey: ByteArray): Boolean

    /** Returns true if this wallet knows the script corresponding to the given hash.  */
    fun isPayToScriptHashMine(payToScriptHash: ByteArray): Boolean

    /** Returns transactions from a specific pool.  */
    fun getTransactionPool(pool: WalletTransaction.Pool): Map<Sha256Hash, Transaction>
}
