/*
 * Copyright 2013 Google Inc.
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
import com.google.common.util.concurrent.*
import org.bitcoinj.utils.*
import org.bitcoinj.wallet.Wallet
import org.slf4j.*

import javax.annotation.*
import java.util.*
import java.util.concurrent.*

import com.google.common.base.Preconditions.checkState
import org.bitcoinj.core.listeners.PreMessageReceivedEventListener

/**
 * Represents a single transaction broadcast that we are performing. A broadcast occurs after a new transaction is created
 * (typically by a [Wallet] and needs to be sent to the network. A broadcast can succeed or fail. A success is
 * defined as seeing the transaction be announced by peers via inv messages, thus indicating their acceptance. A failure
 * is defined as not reaching acceptance within a timeout period, or getting an explicit reject message from a peer
 * indicating that the transaction was not acceptable.
 */
open class TransactionBroadcast {

    private val future = SettableFuture.create<Transaction>()
    private val peerGroup: PeerGroup?
    private val tx: Transaction
    private var minConnections: Int = 0
    private var numWaitingFor: Int = 0

    // Tracks which nodes sent us a reject message about this broadcast, if any. Useful for debugging.
    private val rejects = Collections.synchronizedMap(HashMap<Peer, RejectMessage>())

    private val rejectionListener = object : PreMessageReceivedEventListener {
        override fun onPreMessageReceived(peer: Peer, m: Message): Message {
            if (m is RejectMessage) {
                if (tx.hash == m.rejectedObjectHash) {
                    rejects.put(peer, m)
                    val size = rejects.size
                    val threshold = Math.round(numWaitingFor / 2.0)
                    if (size > threshold) {
                        log.warn("Threshold for considering broadcast rejected has been reached ({}/{})", size, threshold)
                        future.setException(RejectedTransactionException(tx, m))
                        peerGroup!!.removePreMessageReceivedEventListener(this)
                    }
                }
            }
            return m
        }
    }

    private var numSeemPeers: Int = 0
    private var mined: Boolean = false

    private var callback: ProgressCallback? = null
    private var progressCallbackExecutor: Executor? = null

    internal constructor(peerGroup: PeerGroup, tx: Transaction) {
        this.peerGroup = peerGroup
        this.tx = tx
        this.minConnections = Math.max(1, peerGroup.minBroadcastConnections)
    }

    // Only for mock broadcasts.
    private constructor(tx: Transaction) {
        this.peerGroup = null
        this.tx = tx
    }

    open fun future(): ListenableFuture<Transaction> {
        return future
    }

    fun setMinConnections(minConnections: Int) {
        this.minConnections = minConnections
    }

    open fun broadcast(): ListenableFuture<Transaction> {
        peerGroup!!.addPreMessageReceivedEventListener(Threading.SAME_THREAD, rejectionListener)
        log.info("Waiting for {} peers required for broadcast, we have {} ...", minConnections, peerGroup.connectedPeers.size)
        peerGroup.waitForPeers(minConnections).addListener(EnoughAvailablePeers(), Threading.SAME_THREAD)
        return future
    }

    private inner class EnoughAvailablePeers : Runnable {
        override fun run() {
            // We now have enough connected peers to send the transaction.
            // This can be called immediately if we already have enough. Otherwise it'll be called from a peer
            // thread.

            // We will send the tx simultaneously to half the connected peers and wait to hear back from at least half
            // of the other half, i.e., with 4 peers connected we will send the tx to 2 randomly chosen peers, and then
            // wait for it to show up on one of the other two. This will be taken as sign of network acceptance. As can
            // be seen, 4 peers is probably too little - it doesn't taken many broken peers for tx propagation to have
            // a big effect.
            var peers = peerGroup!!.connectedPeers    // snapshots
            // Prepare to send the transaction by adding a listener that'll be called when confidence changes.
            // Only bother with this if we might actually hear back:
            if (minConnections > 1)
                tx.confidence.addEventListener(ConfidenceChange())
            // Bitcoin Core sends an inv in this case and then lets the peer request the tx data. We just
            // blast out the TX here for a couple of reasons. Firstly it's simpler: in the case where we have
            // just a single connection we don't have to wait for getdata to be received and handled before
            // completing the future in the code immediately below. Secondly, it's faster. The reason the
            // Bitcoin Core sends an inv is privacy - it means you can't tell if the peer originated the
            // transaction or not. However, we are not a fully validating node and this is advertised in
            // our version message, as SPV nodes cannot relay it doesn't give away any additional information
            // to skip the inv here - we wouldn't send invs anyway.
            val numConnected = peers.size
            val numToBroadcastTo = Math.max(1, Math.round(Math.ceil(peers.size / 2.0))).toInt()
            numWaitingFor = Math.ceil((peers.size - numToBroadcastTo) / 2.0).toInt()
            Collections.shuffle(peers, random)
            peers = peers.subList(0, numToBroadcastTo)
            log.info("broadcastTransaction: We have {} peers, adding {} to the memory pool", numConnected, tx.hashAsString)
            log.info("Sending to {} peers, will wait for {}, sending to: {}", numToBroadcastTo, numWaitingFor, Joiner.on(",").join(peers))
            for (peer in peers) {
                try {
                    peer.sendMessage(tx)
                    // We don't record the peer as having seen the tx in the memory pool because we want to track only
                    // how many peers announced to us.
                } catch (e: Exception) {
                    log.error("Caught exception sending to {}", peer, e)
                }

            }
            // If we've been limited to talk to only one peer, we can't wait to hear back because the
            // remote peer won't tell us about transactions we just announced to it for obvious reasons.
            // So we just have to assume we're done, at that point. This happens when we're not given
            // any peer discovery source and the user just calls connectTo() once.
            if (minConnections == 1) {
                peerGroup.removePreMessageReceivedEventListener(rejectionListener)
                future.set(tx)
            }
        }
    }

    private inner class ConfidenceChange : TransactionConfidence.Listener {
        override fun onConfidenceChanged(conf: TransactionConfidence, reason: TransactionConfidence.Listener.ChangeReason) {
            // The number of peers that announced this tx has gone up.
            val numSeenPeers = conf.numBroadcastPeers() + rejects.size
            val mined = tx.appearsInHashes != null
            log.info("broadcastTransaction: {}:  TX {} seen by {} peers{}", reason, tx.hashAsString,
                    numSeenPeers, if (mined) " and mined" else "")

            // Progress callback on the requested thread.
            invokeAndRecord(numSeenPeers, mined)

            if (numSeenPeers >= numWaitingFor || mined) {
                // We've seen the min required number of peers announce the transaction, or it was included
                // in a block. Normally we'd expect to see it fully propagate before it gets mined, but
                // it can be that a block is solved very soon after broadcast, and it's also possible that
                // due to version skew and changes in the relay rules our transaction is not going to
                // fully propagate yet can get mined anyway.
                //
                // Note that we can't wait for the current number of connected peers right now because we
                // could have added more peers after the broadcast took place, which means they won't
                // have seen the transaction. In future when peers sync up their memory pools after they
                // connect we could come back and change this.
                //
                // We're done! It's important that the PeerGroup lock is not held (by this thread) at this
                // point to avoid triggering inversions when the Future completes.
                log.info("broadcastTransaction: {} complete", tx.hash)
                peerGroup!!.removePreMessageReceivedEventListener(rejectionListener)
                conf.removeEventListener(this)
                future.set(tx)  // RE-ENTRANCY POINT
            }
        }
    }

    private fun invokeAndRecord(numSeenPeers: Int, mined: Boolean) {
        synchronized(this) {
            this.numSeemPeers = numSeenPeers
            this.mined = mined
        }
        invokeProgressCallback(numSeenPeers, mined)
    }

    private fun invokeProgressCallback(numSeenPeers: Int, mined: Boolean) {
        var callback: ProgressCallback?
        var executor: Executor?
        synchronized(this) {
            callback = this.callback
            executor = this.progressCallbackExecutor
        }
        if (callback != null) {
            val progress = Math.min(1.0, if (mined) 1.0 else numSeenPeers / numWaitingFor.toDouble())
            checkState(progress >= 0.0 && progress <= 1.0, progress)
            try {
                if (executor == null)
                    callback!!.onBroadcastProgress(progress)
                else
                    executor!!.execute { callback!!.onBroadcastProgress(progress) }
            } catch (e: Throwable) {
                log.error("Exception during progress callback", e)
            }

        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /** An interface for receiving progress information on the propagation of the tx, from 0.0 to 1.0  */
    interface ProgressCallback {
        /**
         * onBroadcastProgress will be invoked on the provided executor when the progress of the transaction
         * broadcast has changed, because the transaction has been announced by another peer or because the transaction
         * was found inside a mined block (in this case progress will go to 1.0 immediately). Any exceptions thrown
         * by this callback will be logged and ignored.
         */
        fun onBroadcastProgress(progress: Double)
    }

    /**
     * Sets the given callback for receiving progress values, which will run on the given executor. If the executor
     * is null then the callback will run on a network thread and may be invoked multiple times in parallel. You
     * probably want to provide your UI thread or Threading.USER_THREAD for the second parameter. If the broadcast
     * has already started then the callback will be invoked immediately with the current progress.
     */
    @JvmOverloads
    fun setProgressCallback(callback: ProgressCallback, executor: Executor? = Threading.USER_THREAD) {
        var shouldInvoke: Boolean
        var num: Int
        var mined: Boolean
        synchronized(this) {
            this.callback = callback
            this.progressCallbackExecutor = executor
            num = this.numSeemPeers
            mined = this.mined
            shouldInvoke = numWaitingFor > 0
        }
        if (shouldInvoke)
            invokeProgressCallback(num, mined)
    }

    companion object {
        private val log = LoggerFactory.getLogger(TransactionBroadcast::class.java!!)

        /** Used for shuffling the peers before broadcast: unit tests can replace this to make themselves deterministic.  */
        @VisibleForTesting
        var random = Random()

        @VisibleForTesting
        fun createMockBroadcast(tx: Transaction, future: SettableFuture<Transaction>): TransactionBroadcast {
            return object : TransactionBroadcast(tx) {
                override fun broadcast(): ListenableFuture<Transaction> {
                    return future
                }

                override fun future(): ListenableFuture<Transaction> {
                    return future
                }
            }
        }
    }
}
/**
 * Sets the given callback for receiving progress values, which will run on the user thread. See
 * [org.bitcoinj.utils.Threading] for details.  If the broadcast has already started then the callback will
 * be invoked immediately with the current progress.
 */
