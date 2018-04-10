/*
 * Copyright 2012 Google Inc.
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

import org.bitcoinj.utils.*

import javax.annotation.*
import java.lang.ref.*
import java.util.*
import java.util.concurrent.locks.*

import com.google.common.base.Preconditions.checkNotNull

/**
 *
 * Tracks transactions that are being announced across the network. Typically one is created for you by a
 * [PeerGroup] and then given to each Peer to update. The current purpose is to let Peers update the confidence
 * (number of peers broadcasting). It helps address an attack scenario in which a malicious remote peer (or several)
 * feeds you invalid transactions, eg, ones that spend coins which don't exist. If you don't see most of the peers
 * announce the transaction within a reasonable time, it may be that the TX is not valid. Alternatively, an attacker
 * may control your entire internet connection: in this scenario counting broadcasting peers does not help you.
 *
 *
 * It is **not** at this time directly equivalent to the Bitcoin Core memory pool, which tracks
 * all transactions not currently included in the best chain - it's simply a cache.
 */
class TxConfidenceTable
/**
 * Creates a table that will track at most the given number of transactions (allowing you to bound memory
 * usage).
 * @param size Max number of transactions to track. The table will fill up to this size then stop growing.
 */
@JvmOverloads constructor(size: Int = MAX_SIZE) {
    protected var lock = Threading.lock("txconfidencetable")
    private val table: LinkedHashMap<Sha256Hash, WeakConfidenceReference>

    // This ReferenceQueue gets entries added to it when they are only weakly reachable, ie, the TxConfidenceTable is the
    // only thing that is tracking the confidence data anymore. We check it from time to time and delete table entries
    // corresponding to expired transactions. In this way memory usage of the system is in line with however many
    // transactions you actually care to track the confidence of. We can still end up with lots of hashes being stored
    // if our peers flood us with invs but the MAX_SIZE param caps this.
    private val referenceQueue: ReferenceQueue<TransactionConfidence>

    private class WeakConfidenceReference(confidence: TransactionConfidence, queue: ReferenceQueue<TransactionConfidence>) : WeakReference<TransactionConfidence>(confidence, queue) {
        var hash: Sha256Hash

        init {
            hash = confidence.transactionHash
        }
    }

    init {
        table = object : LinkedHashMap<Sha256Hash, WeakConfidenceReference>() {
            protected override fun removeEldestEntry(entry: Entry<Sha256Hash, WeakConfidenceReference>?): Boolean {
                // An arbitrary choice to stop the memory used by tracked transactions getting too huge in the event
                // of some kind of DoS attack.
                return size > size
            }
        }
        referenceQueue = ReferenceQueue()
    }

    /**
     * If any transactions have expired due to being only weakly reachable through us, go ahead and delete their
     * table entries - it means we downloaded the transaction and sent it to various event listeners, none of
     * which bothered to keep a reference. Typically, this is because the transaction does not involve any keys that
     * are relevant to any of our wallets.
     */
    private fun cleanTable() {
        lock.lock()
        try {
            var ref: Reference<out TransactionConfidence>
            while ((ref = referenceQueue.poll()) != null) {
                // Find which transaction got deleted by the GC.
                val txRef = ref as WeakConfidenceReference
                // And remove the associated map entry so the other bits of memory can also be reclaimed.
                table.remove(txRef.hash)
            }
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns the number of peers that have seen the given hash recently.
     */
    fun numBroadcastPeers(txHash: Sha256Hash): Int {
        lock.lock()
        try {
            cleanTable()
            val entry = table[txHash]
            if (entry == null) {
                return 0  // No such TX known.
            } else {
                val confidence = entry.get()
                if (confidence == null) {
                    // Such a TX hash was seen, but nothing seemed to care so we ended up throwing away the data.
                    table.remove(txHash)
                    return 0
                } else {
                    return confidence.numBroadcastPeers()
                }
            }
        } finally {
            lock.unlock()
        }
    }

    /**
     * Called by peers when they see a transaction advertised in an "inv" message. It passes the data on to the relevant
     * [org.bitcoinj.core.TransactionConfidence] object, creating it if needed.
     *
     * @return the number of peers that have now announced this hash (including the caller)
     */
    fun seen(hash: Sha256Hash, byPeer: PeerAddress): TransactionConfidence {
        var confidence: TransactionConfidence
        var fresh = false
        lock.lock()
        run {
            cleanTable()
            confidence = getOrCreate(hash)
            fresh = confidence.markBroadcastBy(byPeer)
        }
        lock.unlock()
        if (fresh)
            confidence.queueListeners(TransactionConfidence.Listener.ChangeReason.SEEN_PEERS)
        return confidence
    }

    /**
     * Returns the [TransactionConfidence] for the given hash if we have downloaded it, or null if that tx hash
     * is unknown to the system at this time.
     */
    fun getOrCreate(hash: Sha256Hash): TransactionConfidence {
        checkNotNull(hash)
        lock.lock()
        try {
            val reference = table[hash]
            if (reference != null) {
                val confidence = reference.get()
                if (confidence != null)
                    return confidence
            }
            val newConfidence = TransactionConfidence(hash)
            table.put(hash, WeakConfidenceReference(newConfidence, referenceQueue))
            return newConfidence
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns the [TransactionConfidence] for the given hash if we have downloaded it, or null if that tx hash
     * is unknown to the system at this time.
     */
    operator fun get(hash: Sha256Hash): TransactionConfidence? {
        lock.lock()
        try {
            val ref = table[hash] ?: return null
            return ref.get()
        } finally {
            lock.unlock()
        }
    }

    companion object {

        /** The max size of a table created with the no-args constructor.  */
        val MAX_SIZE = 1000
    }
}
/**
 * Creates a table that will track at most [TxConfidenceTable.MAX_SIZE] entries. You should normally use
 * this constructor.
 */
