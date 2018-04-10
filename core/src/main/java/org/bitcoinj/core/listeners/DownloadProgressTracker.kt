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

package org.bitcoinj.core.listeners

import org.bitcoinj.core.Block
import org.bitcoinj.core.FilteredBlock
import org.bitcoinj.core.Peer
import org.bitcoinj.core.Utils
import com.google.common.util.concurrent.ListenableFuture
import com.google.common.util.concurrent.SettableFuture
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.annotation.*
import java.util.Date
import java.util.Locale
import java.util.concurrent.ExecutionException

/**
 *
 * An implementation of [AbstractPeerDataEventListener] that listens to chain download events and tracks progress
 * as a percentage. The default implementation prints progress to stdout, but you can subclass it and override the
 * progress method to update a GUI instead.
 */
open class DownloadProgressTracker : AbstractPeerDataEventListener() {
    private var originalBlocksLeft = -1
    private var lastPercent = 0
    private val future = SettableFuture.create<Long>()
    private var caughtUp = false

    override fun onChainDownloadStarted(peer: Peer, blocksLeft: Int) {
        if (blocksLeft > 0 && originalBlocksLeft == -1)
            startDownload(blocksLeft)
        // Only mark this the first time, because this method can be called more than once during a chain download
        // if we switch peers during it.
        if (originalBlocksLeft == -1)
            originalBlocksLeft = blocksLeft
        else
            log.info("Chain download switched to {}", peer)
        if (blocksLeft == 0) {
            doneDownload()
            future.set(peer.bestHeight)
        }
    }

    override fun onBlocksDownloaded(peer: Peer, block: Block, filteredBlock: FilteredBlock?, blocksLeft: Int) {
        if (caughtUp)
            return

        if (blocksLeft == 0) {
            caughtUp = true
            doneDownload()
            future.set(peer.bestHeight)
        }

        if (blocksLeft < 0 || originalBlocksLeft <= 0)
            return

        val pct = 100.0 - 100.0 * (blocksLeft / originalBlocksLeft.toDouble())
        if (pct.toInt() != lastPercent) {
            progress(pct, blocksLeft, Date(block.timeSeconds * 1000))
            lastPercent = pct.toInt()
        }
    }

    /**
     * Called when download progress is made.
     *
     * @param pct  the percentage of chain downloaded, estimated
     * @param date the date of the last block downloaded
     */
    protected open fun progress(pct: Double, blocksSoFar: Int, date: Date) {
        log.info(String.format(Locale.US, "Chain download %d%% done with %d blocks to go, block date %s", pct.toInt(), blocksSoFar,
                Utils.dateTimeFormat(date)))
    }

    /**
     * Called when download is initiated.
     *
     * @param blocks the number of blocks to download, estimated
     */
    protected fun startDownload(blocks: Int) {
        log.info("Downloading block chain of size " + blocks + ". " +
                if (blocks > 1000) "This may take a while." else "")
    }

    /**
     * Called when we are done downloading the block chain.
     */
    protected open fun doneDownload() {}

    /**
     * Wait for the chain to be downloaded.
     */
    @Throws(InterruptedException::class)
    fun await() {
        try {
            future.get()
        } catch (e: ExecutionException) {
            throw RuntimeException(e)
        }

    }

    /**
     * Returns a listenable future that completes with the height of the best chain (as reported by the peer) once chain
     * download seems to be finished.
     */
    fun getFuture(): ListenableFuture<Long> {
        return future
    }

    companion object {
        private val log = LoggerFactory.getLogger(DownloadProgressTracker::class.java!!)
    }
}
