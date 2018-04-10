/*
 * Copyright 2011 Google Inc.
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
import org.bitcoinj.core.GetDataMessage
import org.bitcoinj.core.Message
import org.bitcoinj.core.PeerAddress
import org.bitcoinj.core.Peer
import org.bitcoinj.core.Transaction
import javax.annotation.*

/**
 * Deprecated: implement the more specific event listener interfaces instead to fill out only what you need
 */
@Deprecated("")
abstract class AbstractPeerEventListener : AbstractPeerDataEventListener(), PeerConnectionEventListener, OnTransactionBroadcastListener {
    override fun onBlocksDownloaded(peer: Peer, block: Block, filteredBlock: FilteredBlock?, blocksLeft: Int) {}

    override fun onChainDownloadStarted(peer: Peer, blocksLeft: Int) {}

    override fun onPreMessageReceived(peer: Peer, m: Message): Message {
        // Just pass the message right through for further processing.
        return m
    }

    override fun onTransaction(peer: Peer, t: Transaction) {}

    override fun getData(peer: Peer, m: GetDataMessage): List<Message>? {
        return null
    }

    override fun onPeersDiscovered(peerAddresses: Set<PeerAddress>) {}

    override fun onPeerConnected(peer: Peer, peerCount: Int) {}

    override fun onPeerDisconnected(peer: Peer, peerCount: Int) {}
}
