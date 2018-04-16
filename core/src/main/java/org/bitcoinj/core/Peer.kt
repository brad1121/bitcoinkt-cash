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

import com.google.common.base.*
import com.google.common.base.Objects
import org.bitcoinj.core.listeners.*
import org.bitcoinj.net.StreamConnection
import org.bitcoinj.store.BlockStore
import org.bitcoinj.store.BlockStoreException
import org.bitcoinj.utils.ListenerRegistration
import org.bitcoinj.utils.Threading
import org.bitcoinj.wallet.Wallet

import com.google.common.collect.Lists
import com.google.common.util.concurrent.FutureCallback
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import com.google.common.util.concurrent.SettableFuture
import net.jcip.annotations.GuardedBy
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.*
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock

import com.google.common.base.Preconditions.checkNotNull
import com.google.common.base.Preconditions.checkState

/**
 *
 * A Peer handles the high level communication with a Bitcoin node, extending a [PeerSocketHandler] which
 * handles low-level message (de)serialization.
 *
 *
 * Note that timeouts are handled by the extended
 * [org.bitcoinj.net.AbstractTimeoutHandler] and timeout is automatically disabled (using
 * [org.bitcoinj.net.AbstractTimeoutHandler.setTimeoutEnabled]) once the version
 * handshake completes.
 */
abstract class Peer : PeerSocketHandler {
/**
 *
 * Construct a peer that reads/writes from the given block chain. Transactions stored in a [org.bitcoinj.core.TxConfidenceTable]
 * will have their confidence levels updated when a peer announces it, to reflect the greater likelyhood that
 * the transaction is valid.
 *
 *
 * Note that this does **NOT** make a connection to the given remoteAddress, it only creates a handler for a
 * connection. If you want to create a one-off connection, create a Peer and pass it to
 * [org.bitcoinj.net.NioClientManager.openConnection]
 * or
 * [org.bitcoinj.net.NioClient.NioClient].
 *
 *
 * The remoteAddress provided should match the remote address of the peer which is being connected to, and is
 * used to keep track of which peers relayed transactions and offer more descriptive logging.
 */
 constructor(params: NetworkParameters, ver: VersionMessage, remoteAddress: PeerAddress,
                           blockChain: AbstractBlockChain?, downloadTxDependencyDepth: Int = Integer.MAX_VALUE) : PeerSocketHandler(params, remoteAddress) {
    Peer(params,ver,remoteAddress,blockChain)
}

    protected val lock = Threading.lock("peer")

    private val params: NetworkParameters
    private val context: Context?

    private val blocksDownloadedEventListeners = CopyOnWriteArrayList<ListenerRegistration<BlocksDownloadedEventListener>>()
    private val chainDownloadStartedEventListeners = CopyOnWriteArrayList<ListenerRegistration<ChainDownloadStartedEventListener>>()
    private val connectedEventListeners = CopyOnWriteArrayList<ListenerRegistration<PeerConnectedEventListener>>()
    private val disconnectedEventListeners = CopyOnWriteArrayList<ListenerRegistration<PeerDisconnectedEventListener>>()
    private val getDataEventListeners = CopyOnWriteArrayList<ListenerRegistration<GetDataEventListener>>()
    private val preMessageReceivedEventListeners = CopyOnWriteArrayList<ListenerRegistration<PreMessageReceivedEventListener>>()
    private val onTransactionEventListeners = CopyOnWriteArrayList<ListenerRegistration<OnTransactionBroadcastListener>>()
    // Whether to try and download blocks and transactions from this peer. Set to false by PeerGroup if not the
    // primary peer. This is to avoid redundant work and concurrency problems with downloading the same chain
    // in parallel.
    /**
     * Returns true if this peer will try and download things it is sent in "inv" messages. Normally you only need
     * one peer to be downloading data. Defaults to true.
     */
    /**
     * If set to false, the peer won't try and fetch blocks and transactions it hears about. Normally, only one
     * peer should download missing blocks. Defaults to true. Changing this value from false to true may trigger
     * a request to the remote peer for the contents of its memory pool, if Bloom filtering is active.
     */
    @Volatile
    var isDownloadData: Boolean = false
    // The version data to announce to the other side of the connections we make: useful for setting our "user agent"
    // equivalent and other things.
    /** Returns version data we announce to our remote peers.  */
    val versionMessage: VersionMessage
    // Maximum depth up to which pending transaction dependencies are downloaded, or 0 for disabled.
    @Volatile private var vDownloadTxDependencyDepth: Int = 0
    // How many block messages the peer has announced to us. Peers only announce blocks that attach to their best chain
    // so we can use this to calculate the height of the peers chain, by adding it to the initial height in the version
    // message. This method can go wrong if the peer re-orgs onto a shorter (but harder) chain, however, this is rare.
    private val blocksAnnounced = AtomicInteger()
    // Each wallet added to the peer will be notified of downloaded transaction data.
    private val wallets: CopyOnWriteArrayList<Wallet>
    // A time before which we only download block headers, after that point we download block bodies.
    @GuardedBy("lock") private var fastCatchupTimeSecs: Long = 0
    // Whether we are currently downloading headers only or block bodies. Starts at true. If the fast catchup time is
    // set AND our best block is before that date, switch to false until block headers beyond that point have been
    // received at which point it gets set to true again. This isn't relevant unless vDownloadData is true.
    @GuardedBy("lock") private var downloadBlockBodies = true
    // Whether to request filtered blocks instead of full blocks if the protocol version allows for them.
    @GuardedBy("lock") private var useFilteredBlocks = false
    // The current Bloom filter set on the connection, used to tell the remote peer what transactions to send us.
    @Volatile private var vBloomFilter: BloomFilter? = null
    // The last filtered block we received, we're waiting to fill it out with transactions.
    private var currentFilteredBlock: FilteredBlock? = null
    // How many filtered blocks have been received during the lifetime of this connection. Used to decide when to
    // refresh the server-side side filter by sending a new one (it degrades over time as false positives are added
    // on the remote side, see BIP 37 for a discussion of this).
    // TODO: Is this still needed? It should not be since the auto FP tracking logic was added.
    private var filteredBlocksReceived: Int = 0
    // If non-null, we should discard incoming filtered blocks because we ran out of keys and are awaiting a new filter
    // to be calculated by the PeerGroup. The discarded block hashes should be added here so we can re-request them
    // once we've recalculated and resent a new filter.
    @GuardedBy("lock") private var awaitingFreshFilter: MutableList<Sha256Hash>? = null
    // Keeps track of things we requested internally with getdata but didn't receive yet, so we can avoid re-requests.
    // It's not quite the same as getDataFutures, as this is used only for getdatas done as part of downloading
    // the chain and so is lighter weight (we just keep a bunch of hashes not futures).
    //
    // It is important to avoid a nasty edge case where we can end up with parallel chain downloads proceeding
    // simultaneously if we were to receive a newly solved block whilst parts of the chain are streaming to us.
    private val pendingBlockDownloads = HashSet<Sha256Hash>()
    // Keep references to TransactionConfidence objects for transactions that were announced by a remote peer, but
    // which we haven't downloaded yet. These objects are de-duplicated by the TxConfidenceTable class.
    // Once the tx is downloaded (by some peer), the Transaction object that is created will have a reference to
    // the confidence object held inside it, and it's then up to the event listeners that receive the Transaction
    // to keep it pinned to the root set if they care about this data.
    private val pendingTxDownloads = HashSet<TransactionConfidence>()
    // The lowest version number we're willing to accept. Lower than this will result in an immediate disconnect.
    @Volatile private var vMinProtocolVersion: Int = 0
    // TODO: The types/locking should be rationalised a bit.
    private val getDataFutures: CopyOnWriteArrayList<GetDataRequest>
    @GuardedBy("getAddrFutures") private val getAddrFutures: LinkedList<SettableFuture<AddressMessage>>
    @GuardedBy("lock") private var getutxoFutures: LinkedList<SettableFuture<UTXOsMessage>>? = null

    // Outstanding pings against this peer and how long the last one took to complete.
    private val lastPingTimesLock = ReentrantLock()
    @GuardedBy("lastPingTimesLock") private var lastPingTimes: LongArray? = null
    private val pendingPings: CopyOnWriteArrayList<PendingPing>

    /** Returns version data announced by the remote peer.  */
    @Volatile
    var peerVersionMessage: VersionMessage? = null
        private set

    // A settable future which completes (with this) when the connection is open
    private val connectionOpenFuture = SettableFuture.create<Peer>()
    private val outgoingVersionHandshakeFuture = SettableFuture.create<Peer>()
    private val incomingVersionHandshakeFuture = SettableFuture.create<Peer>()
    val versionHandshakeFuture = Futures.transform<List<Peer>, Peer>(
            Futures.allAsList(outgoingVersionHandshakeFuture, incomingVersionHandshakeFuture),
            object : Function<List<Peer>, Peer> {

                override fun apply(peers: List<Peer>?): Peer? {
                    checkNotNull<List<Peer>>(peers)
                    checkState(peers!!.size == 2 && peers[0] === peers[1])
                    return peers[0]
                }
            })

    /** Sends a getaddr request to the peer and returns a future that completes with the answer once the peer has replied.  */
    val addr: ListenableFuture<AddressMessage>
        get() {
            val future = SettableFuture.create<AddressMessage>()
            synchronized(getAddrFutures) {
                getAddrFutures.add(future)
            }
            sendMessage(GetAddrMessage(params))
            return future
        }

    // Keep track of the last request we made to the peer in blockChainDownloadLocked so we can avoid redundant and harmful
    // getblocks requests.
    @GuardedBy("lock")
    private var lastGetBlocksBegin: Sha256Hash? = null
    @GuardedBy("lock")
    private var lastGetBlocksEnd: Sha256Hash? = null

    /**
     * Returns the elapsed time of the last ping/pong cycle. If [org.bitcoinj.core.Peer.ping] has never
     * been called or we did not hear back the "pong" message yet, returns [Long.MAX_VALUE].
     */
    val lastPingTime: Long
        get() {
            lastPingTimesLock.lock()
            try {
                return if (lastPingTimes == null) java.lang.Long.MAX_VALUE else lastPingTimes!![lastPingTimes!!.size - 1]
            } finally {
                lastPingTimesLock.unlock()
            }
        }

    /**
     * Returns a moving average of the last N ping/pong cycles. If [org.bitcoinj.core.Peer.ping] has never
     * been called or we did not hear back the "pong" message yet, returns [Long.MAX_VALUE]. The moving average
     * window is 5 buckets.
     */
    val pingTime: Long
        get() {
            lastPingTimesLock.lock()
            try {
                if (lastPingTimes == null)
                    return java.lang.Long.MAX_VALUE
                var sum: Long = 0
                for (i in lastPingTimes!!) sum += i
                return (sum.toDouble() / lastPingTimes!!.size).toLong()
            } finally {
                lastPingTimesLock.unlock()
            }
        }

    /**
     * Returns the difference between our best chain height and the peers, which can either be positive if we are
     * behind the peer, or negative if the peer is ahead of us.
     */
    // Chain will overflow signed int blocks in ~41,000 years.
    // chainHeight should not be zero/negative because we shouldn't have given the user a Peer that is to another
    // client-mode node, nor should it be unconnected. If that happens it means the user overrode us somewhere or
    // there is a bug in the peer management code.
    val peerBlockHeightDifference: Int
        get() {
            checkNotNull<AbstractBlockChain>(blockChain, "No block chain configured")
            val chainHeight = bestHeight.toInt()
            checkState(params.allowEmptyPeerChain() || chainHeight > 0, "Connected to peer with zero/negative chain height", chainHeight)
            return chainHeight - blockChain!!.bestChainHeight
        }

    private val isNotFoundMessageSupported: Boolean
        get() = peerVersionMessage!!.clientVersion >= NotFoundMessage.MIN_PROTOCOL_VERSION

    /**
     * @return the height of the best chain as claimed by peer: sum of its ver announcement and blocks announced since.
     */
    val bestHeight: Long
        get() = peerVersionMessage!!.bestHeight + blocksAnnounced.get()

    /**
     * Returns the last [BloomFilter] set by [Peer.setBloomFilter]. Bloom filters tell
     * the remote node what transactions to send us, in a compact manner.
     */
    /**
     *
     * Sets a Bloom filter on this connection. This will cause the given [BloomFilter] object to be sent to the
     * remote peer and if either a memory pool has been set using the constructor or the
     * vDownloadData property is true, a [MemoryPoolMessage] is sent as well to trigger downloading of any
     * pending transactions that may be relevant.
     *
     *
     * The Peer does not automatically request filters from any wallets added using [Peer.addWallet].
     * This is to allow callers to avoid redundantly recalculating the same filter repeatedly when using multiple peers
     * and multiple wallets together.
     *
     *
     * Therefore, you should not use this method if your app uses a [PeerGroup]. It is called for you.
     *
     *
     * If the remote peer doesn't support Bloom filtering, then this call is ignored. Once set you presently cannot
     * unset a filter, though the underlying p2p protocol does support it.
     */
    var bloomFilter: BloomFilter?
        get() = vBloomFilter
        set(filter) = setBloomFilter(filter, true)

    /**
     * Returns true if this peer will use getdata/notfound messages to walk backwards through transaction dependencies
     * before handing the transaction off to the wallet. The wallet can do risk analysis on pending/recent transactions
     * to try and discover if a pending tx might be at risk of double spending.
     */
    /**
     * Sets if this peer will use getdata/notfound messages to walk backwards through transaction dependencies
     * before handing the transaction off to the wallet. The wallet can do risk analysis on pending/recent transactions
     * to try and discover if a pending tx might be at risk of double spending.
     */
    var isDownloadTxDependencies: Boolean
        get() = vDownloadTxDependencyDepth > 0
        set(enable) {
            vDownloadTxDependencyDepth = if (enable) Integer.MAX_VALUE else 0
        }

    // When an API user explicitly requests a block or transaction from a peer, the InventoryItem is put here
    // whilst waiting for the response. Is not used for downloads Peer generates itself.
    private class GetDataRequest(internal val hash: Sha256Hash, internal val future: SettableFuture<*>)

    /**
     *
     * Construct a peer that reads/writes from the given block chain.
     *
     *
     * Note that this does **NOT** make a connection to the given remoteAddress, it only creates a handler for a
     * connection. If you want to create a one-off connection, create a Peer and pass it to
     * [org.bitcoinj.net.NioClientManager.openConnection]
     * or
     * [org.bitcoinj.net.NioClient.NioClient].
     *
     *
     * The remoteAddress provided should match the remote address of the peer which is being connected to, and is
     * used to keep track of which peers relayed transactions and offer more descriptive logging.
     */
    constructor(params: NetworkParameters, ver: VersionMessage, chain: AbstractBlockChain?, remoteAddress: PeerAddress) : this(params, ver, remoteAddress, chain) {}

    init {
        this.params = Preconditions.checkNotNull(params)
        this.versionMessage = Preconditions.checkNotNull(ver)
        this.vDownloadTxDependencyDepth = if (blockChain != null) downloadTxDependencyDepth else 0
        this.isDownloadData = blockChain != null
        this.getDataFutures = CopyOnWriteArrayList()
        this.getAddrFutures = LinkedList()
        this.fastCatchupTimeSecs = params.genesisBlock.timeSeconds
        this.pendingPings = CopyOnWriteArrayList()
        this.vMinProtocolVersion = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.PONG)
        this.wallets = CopyOnWriteArrayList()
        this.context = Context.get()

        this.versionHandshakeFuture.addListener(Runnable { versionHandshakeComplete() }, Threading.SAME_THREAD)
    }// Allowed to be null.

    /**
     *
     * Construct a peer that reads/writes from the given chain. Automatically creates a VersionMessage for you from
     * the given software name/version strings, which should be something like "MySimpleTool", "1.0" and which will tell
     * the remote node to relay transaction inv messages before it has received a filter.
     *
     *
     * Note that this does **NOT** make a connection to the given remoteAddress, it only creates a handler for a
     * connection. If you want to create a one-off connection, create a Peer and pass it to
     * [org.bitcoinj.net.NioClientManager.openConnection]
     * or
     * [org.bitcoinj.net.NioClient.NioClient].
     *
     *
     * The remoteAddress provided should match the remote address of the peer which is being connected to, and is
     * used to keep track of which peers relayed transactions and offer more descriptive logging.
     */
    constructor(params: NetworkParameters, blockChain: AbstractBlockChain, peerAddress: PeerAddress, thisSoftwareName: String, thisSoftwareVersion: String) : this(params, VersionMessage(params, blockChain.bestChainHeight), blockChain, peerAddress) {
        this.versionMessage.appendToSubVer(thisSoftwareName, thisSoftwareVersion, null)
    }

    /** Deprecated: use the more specific event handler methods instead  */
    @Deprecated("")
    fun addEventListener(listener: AbstractPeerEventListener) {
        addBlocksDownloadedEventListener(Threading.USER_THREAD, listener)
        addChainDownloadStartedEventListener(Threading.USER_THREAD, listener)
        addConnectedEventListener(Threading.USER_THREAD, listener)
        addDisconnectedEventListener(Threading.USER_THREAD, listener)
        addGetDataEventListener(Threading.USER_THREAD, listener)
        addOnTransactionBroadcastListener(Threading.USER_THREAD, listener)
        addPreMessageReceivedEventListener(Threading.USER_THREAD, listener)
    }

    /** Deprecated: use the more specific event handler methods instead  */
    @Deprecated("")
    fun addEventListener(listener: AbstractPeerEventListener, executor: Executor) {
        addBlocksDownloadedEventListener(executor, listener)
        addChainDownloadStartedEventListener(executor, listener)
        addConnectedEventListener(executor, listener)
        addDisconnectedEventListener(executor, listener)
        addGetDataEventListener(executor, listener)
        addOnTransactionBroadcastListener(executor, listener)
        addPreMessageReceivedEventListener(executor, listener)
    }

    /** Deprecated: use the more specific event handler methods instead  */
    @Deprecated("")
    fun removeEventListener(listener: AbstractPeerEventListener) {
        removeBlocksDownloadedEventListener(listener)
        removeChainDownloadStartedEventListener(listener)
        removeConnectedEventListener(listener)
        removeDisconnectedEventListener(listener)
        removeGetDataEventListener(listener)
        removeOnTransactionBroadcastListener(listener)
        removePreMessageReceivedEventListener(listener)
    }

    /** Registers a listener that is invoked when new blocks are downloaded.  */
    fun addBlocksDownloadedEventListener(listener: BlocksDownloadedEventListener) {
        addBlocksDownloadedEventListener(Threading.USER_THREAD, listener)
    }

    /** Registers a listener that is invoked when new blocks are downloaded.  */
    fun addBlocksDownloadedEventListener(executor: Executor, listener: BlocksDownloadedEventListener) {
        blocksDownloadedEventListeners.add(ListenerRegistration(listener, executor))
    }

    /** Registers a listener that is invoked when a blockchain downloaded starts.  */
    fun addChainDownloadStartedEventListener(listener: ChainDownloadStartedEventListener) {
        addChainDownloadStartedEventListener(Threading.USER_THREAD, listener)
    }

    /** Registers a listener that is invoked when a blockchain downloaded starts.  */
    fun addChainDownloadStartedEventListener(executor: Executor, listener: ChainDownloadStartedEventListener) {
        chainDownloadStartedEventListeners.add(ListenerRegistration(listener, executor))
    }

    /** Registers a listener that is invoked when a peer is connected.  */
    fun addConnectedEventListener(listener: PeerConnectedEventListener) {
        addConnectedEventListener(Threading.USER_THREAD, listener)
    }

    /** Registers a listener that is invoked when a peer is connected.  */
    fun addConnectedEventListener(executor: Executor, listener: PeerConnectedEventListener) {
        connectedEventListeners.add(ListenerRegistration(listener, executor))
    }

    /** Registers a listener that is invoked when a peer is disconnected.  */
    fun addDisconnectedEventListener(listener: PeerDisconnectedEventListener) {
        addDisconnectedEventListener(Threading.USER_THREAD, listener)
    }

    /** Registers a listener that is invoked when a peer is disconnected.  */
    fun addDisconnectedEventListener(executor: Executor, listener: PeerDisconnectedEventListener) {
        disconnectedEventListeners.add(ListenerRegistration(listener, executor))
    }

    /** Registers a listener that is called when messages are received.  */
    fun addGetDataEventListener(listener: GetDataEventListener) {
        addGetDataEventListener(Threading.USER_THREAD, listener)
    }

    /** Registers a listener that is called when messages are received.  */
    fun addGetDataEventListener(executor: Executor, listener: GetDataEventListener) {
        getDataEventListeners.add(ListenerRegistration(listener, executor))
    }

    /** Registers a listener that is called when a transaction is broadcast across the network  */
    fun addOnTransactionBroadcastListener(listener: OnTransactionBroadcastListener) {
        addOnTransactionBroadcastListener(Threading.USER_THREAD, listener)
    }

    /** Registers a listener that is called when a transaction is broadcast across the network  */
    fun addOnTransactionBroadcastListener(executor: Executor, listener: OnTransactionBroadcastListener) {
        onTransactionEventListeners.add(ListenerRegistration(listener, executor))
    }

    /** Registers a listener that is called immediately before a message is received  */
    fun addPreMessageReceivedEventListener(listener: PreMessageReceivedEventListener) {
        addPreMessageReceivedEventListener(Threading.USER_THREAD, listener)
    }

    /** Registers a listener that is called immediately before a message is received  */
    fun addPreMessageReceivedEventListener(executor: Executor, listener: PreMessageReceivedEventListener) {
        preMessageReceivedEventListeners.add(ListenerRegistration(listener, executor))
    }

    fun removeBlocksDownloadedEventListener(listener: BlocksDownloadedEventListener): Boolean {
        return ListenerRegistration.removeFromList(listener, blocksDownloadedEventListeners)
    }

    fun removeChainDownloadStartedEventListener(listener: ChainDownloadStartedEventListener): Boolean {
        return ListenerRegistration.removeFromList(listener, chainDownloadStartedEventListeners)
    }

    fun removeConnectedEventListener(listener: PeerConnectedEventListener): Boolean {
        return ListenerRegistration.removeFromList(listener, connectedEventListeners)
    }

    fun removeDisconnectedEventListener(listener: PeerDisconnectedEventListener): Boolean {
        return ListenerRegistration.removeFromList(listener, disconnectedEventListeners)
    }

    fun removeGetDataEventListener(listener: GetDataEventListener): Boolean {
        return ListenerRegistration.removeFromList(listener, getDataEventListeners)
    }

    fun removeOnTransactionBroadcastListener(listener: OnTransactionBroadcastListener): Boolean {
        return ListenerRegistration.removeFromList(listener, onTransactionEventListeners)
    }

    fun removePreMessageReceivedEventListener(listener: PreMessageReceivedEventListener): Boolean {
        return ListenerRegistration.removeFromList(listener, preMessageReceivedEventListeners)
    }

    override fun toString(): String {
        val addr = address
        // if null, it's a user-provided NetworkConnection object
        return addr?.toString() ?: "Peer()"
    }

    override fun timeoutOccurred() {
        super.timeoutOccurred()
        if (!connectionOpenFuture.isDone) {
            connectionClosed()  // Invoke the event handlers to tell listeners e.g. PeerGroup that we never managed to connect.
        }
    }

    override fun connectionClosed() {
        for (registration in disconnectedEventListeners) {
            registration.executor.execute { registration.listener.onPeerDisconnected(this@Peer, 0) }
        }
    }

    override fun connectionOpened() {
        // Announce ourselves. This has to come first to connect to clients beyond v0.3.20.2 which wait to hear
        // from us until they send their version message back.
        val address = address
        log.info("Announcing to {} as: {}", if (address == null) "Peer" else address.toSocketAddress(), versionMessage.subVer)
        sendMessage(versionMessage)
        connectionOpenFuture.set(this)
        // When connecting, the remote peer sends us a version message with various bits of
        // useful data in it. We need to know the peer protocol version before we can talk to it.
    }

    /**
     * Provides a ListenableFuture that can be used to wait for the socket to connect.  A socket connection does not
     * mean that protocol handshake has occurred.
     */
    fun getConnectionOpenFuture(): ListenableFuture<Peer> {
        return connectionOpenFuture
    }

    @Throws(Exception::class)
    override fun processMessage(m: Message?) {
        var m = m
        // Allow event listeners to filter the message stream. Listeners are allowed to drop messages by
        // returning null.
        for (registration in preMessageReceivedEventListeners) {
            // Skip any listeners that are supposed to run in another thread as we don't want to block waiting
            // for it, which might cause circular deadlock.
            if (registration.executor === Threading.SAME_THREAD) {
                m = registration.listener.onPreMessageReceived(this, m)
                if (m == null) break
            }
        }
        if (m == null) return

        // If we are in the middle of receiving transactions as part of a filtered block push from the remote node,
        // and we receive something that's not a transaction, then we're done.
        if (currentFilteredBlock != null && m !is Transaction) {
            endFilteredBlock(currentFilteredBlock)
            currentFilteredBlock = null
        }

        // No further communication is possible until version handshake is complete.
        if (!(m is VersionMessage || m is VersionAck
                || versionHandshakeFuture.isDone() && !versionHandshakeFuture.isCancelled()))
            throw ProtocolException(
                    "Received " + m.javaClass.getSimpleName() + " before version handshake is complete.")

        if (m is Ping) {
            processPing((m as Ping?)!!)
        } else if (m is Pong) {
            processPong(m as Pong?)
        } else if (m is NotFoundMessage) {
            // This is sent to us when we did a getdata on some transactions that aren't in the peers memory pool.
            // Because NotFoundMessage is a subclass of InventoryMessage, the test for it must come before the next.
            processNotFoundMessage(m as NotFoundMessage?)
        } else if (m is InventoryMessage) {
            processInv(m as InventoryMessage?)
        } else if (m is Block) {
            processBlock(m as Block?)
        } else if (m is FilteredBlock) {
            startFilteredBlock(m as FilteredBlock?)
        } else if (m is Transaction) {
            processTransaction(m as Transaction?)
        } else if (m is GetDataMessage) {
            processGetData(m as GetDataMessage?)
        } else if (m is AddressMessage) {
            // We don't care about addresses of the network right now. But in future,
            // we should save them in the wallet so we don't put too much load on the seed nodes and can
            // properly explore the network.
            processAddressMessage(m as AddressMessage?)
        } else if (m is HeadersMessage) {
            processHeaders(m as HeadersMessage?)
        } else if (m is AlertMessage) {
            processAlert(m as AlertMessage?)
        } else if (m is VersionMessage) {
            processVersionMessage(m as VersionMessage?)
        } else if (m is VersionAck) {
            processVersionAck(m as VersionAck?)
        } else if (m is UTXOsMessage) {
            processUTXOMessage(m as UTXOsMessage?)
        } else if (m is RejectMessage) {
            log.error("{} {}: Received {}", this, peerVersionMessage!!.subVer, m)
        } else {
            log.warn("{}: Received unhandled message: {}", this, m)
        }
    }

    protected fun processUTXOMessage(m: UTXOsMessage) {
        var future: SettableFuture<UTXOsMessage>? = null
        lock.lock()
        try {
            if (getutxoFutures != null)
                future = getutxoFutures!!.pollFirst()
        } finally {
            lock.unlock()
        }
        if (future != null)
            future.set(m)
    }

    private fun processAddressMessage(m: AddressMessage) {
        var future: SettableFuture<AddressMessage>?
        synchronized(getAddrFutures) {
            future = getAddrFutures.poll()
            if (future == null)
            // Not an addr message we are waiting for.
                return
        }
        future!!.set(m)
    }

    @Throws(ProtocolException::class)
    private fun processVersionMessage(m: VersionMessage) {
        if (peerVersionMessage != null)
            throw ProtocolException("Got two version messages from peer")
        peerVersionMessage = m
        // Switch to the new protocol version.
        val peerTime = peerVersionMessage!!.time * 1000
        log.info("{}: Got version={}, subVer='{}', services=0x{}, time={}, blocks={}",
                this,
                peerVersionMessage!!.clientVersion,
                peerVersionMessage!!.subVer,
                peerVersionMessage!!.localServices,
                String.format(Locale.US, "%tF %tT", peerTime, peerTime),
                peerVersionMessage!!.bestHeight)
        // bitcoinj is a client mode implementation. That means there's not much point in us talking to other client
        // mode nodes because we can't download the data from them we need to find/verify transactions. Some bogus
        // implementations claim to have a block chain in their services field but then report a height of zero, filter
        // them out here.
        if (!peerVersionMessage!!.hasBlockChain() || !params.allowEmptyPeerChain() && peerVersionMessage!!.bestHeight == 0L) {
            // Shut down the channel gracefully.
            log.info("{}: Peer does not have a copy of the block chain.", this)
            close()
            return
        }
        if (peerVersionMessage!!.localServices and VersionMessage.NODE_BITCOIN_CASH != VersionMessage.NODE_BITCOIN_CASH.toLong()) {
            log.info("{}: Peer follows an incompatible block chain.", this)
            // Shut down the channel gracefully.
            close()
            return
        }
        if (peerVersionMessage!!.bestHeight < 0)
        // In this case, it's a protocol violation.
            throw ProtocolException("Peer reports invalid best height: " + peerVersionMessage!!.bestHeight)
        // Now it's our turn ...
        // Send an ACK message stating we accept the peers protocol version.
        sendMessage(VersionAck())
        log.debug("{}: Incoming version handshake complete.", this)
        incomingVersionHandshakeFuture.set(this)
    }

    @Throws(ProtocolException::class)
    private fun processVersionAck(m: VersionAck) {
        if (peerVersionMessage == null) {
            throw ProtocolException("got a version ack before version")
        }
        if (outgoingVersionHandshakeFuture.isDone) {
            throw ProtocolException("got more than one version ack")
        }
        log.debug("{}: Outgoing version handshake complete.", this)
        outgoingVersionHandshakeFuture.set(this)
    }

    private fun versionHandshakeComplete() {
        log.debug("{}: Handshake complete.", this)
        setTimeoutEnabled(false)
        for (registration in connectedEventListeners) {
            registration.executor.execute { registration.listener.onPeerConnected(this@Peer, 1) }
        }
        // We check min version after onPeerConnected as channel.close() will
        // call onPeerDisconnected, and we should probably call onPeerConnected first.
        val version = vMinProtocolVersion
        if (peerVersionMessage!!.clientVersion < version) {
            log.warn("Connected to a peer speaking protocol version {} but need {}, closing",
                    peerVersionMessage!!.clientVersion, version)
            close()
        }
    }

    protected fun startFilteredBlock(m: FilteredBlock) {
        // Filtered blocks come before the data that they refer to, so stash it here and then fill it out as
        // messages stream in. We'll call endFilteredBlock when a non-tx message arrives (eg, another
        // FilteredBlock) or when a tx that isn't needed by that block is found. A ping message is sent after
        // a getblocks, to force the non-tx message path.
        currentFilteredBlock = m
        // Potentially refresh the server side filter. Because the remote node adds hits back into the filter
        // to save round-tripping back through us, the filter degrades over time as false positives get added,
        // triggering yet more false positives. We refresh it every so often to get the FP rate back down.
        filteredBlocksReceived++
        if (filteredBlocksReceived % RESEND_BLOOM_FILTER_BLOCK_COUNT == RESEND_BLOOM_FILTER_BLOCK_COUNT - 1) {
            sendMessage(vBloomFilter)
        }
    }

    protected fun processNotFoundMessage(m: NotFoundMessage) {
        // This is received when we previously did a getdata but the peer couldn't find what we requested in it's
        // memory pool. Typically, because we are downloading dependencies of a relevant transaction and reached
        // the bottom of the dependency tree (where the unconfirmed transactions connect to transactions that are
        // in the chain).
        //
        // We go through and cancel the pending getdata futures for the items we were told weren't found.
        for (req in getDataFutures) {
            for (item in m.getItems()) {
                if (item.hash == req.hash) {
                    log.info("{}: Bottomed out dep tree at {}", this, req.hash)
                    req.future.cancel(true)
                    getDataFutures.remove(req)
                    break
                }
            }
        }
    }

    protected fun processAlert(m: AlertMessage) {
        try {
            if (m.isSignatureValid) {
                log.debug("Received alert from peer {}: {}", this, m.statusBar)
            } else {
                log.debug("Received alert with invalid signature from peer {}: {}", this, m.statusBar)
            }
        } catch (t: Throwable) {
            // Signature checking can FAIL on Android platforms before Gingerbread apparently due to bugs in their
            // BigInteger implementations! See https://github.com/bitcoinj/bitcoinj/issues/526 for discussion. As
            // alerts are just optional and not that useful, we just swallow the error here.
            log.error("Failed to check signature: bug in platform libraries?", t)
        }

    }

    @Throws(ProtocolException::class)
    protected fun processHeaders(m: HeadersMessage) {
        // Runs in network loop thread for this peer.
        //
        // This method can run if a peer just randomly sends us a "headers" message (should never happen), or more
        // likely when we've requested them as part of chain download using fast catchup. We need to add each block to
        // the chain if it pre-dates the fast catchup time. If we go past it, we can stop processing the headers and
        // request the full blocks from that point on instead.
        val downloadBlockBodies: Boolean
        val fastCatchupTimeSecs: Long

        lock.lock()
        try {
            if (blockChain == null) {
                // Can happen if we are receiving unrequested data, or due to programmer error.
                log.warn("Received headers when Peer is not configured with a chain.")
                return
            }
            fastCatchupTimeSecs = this.fastCatchupTimeSecs
            downloadBlockBodies = this.downloadBlockBodies
        } finally {
            lock.unlock()
        }

        try {
            checkState(!downloadBlockBodies, toString())
            for (i in 0 until m.blockHeaders!!.size) {
                val header = m.blockHeaders!![i]
                // Process headers until we pass the fast catchup time, or are about to catch up with the head
                // of the chain - always process the last block as a full/filtered block to kick us out of the
                // fast catchup mode (in which we ignore new blocks).
                val passedTime = header.timeSeconds >= fastCatchupTimeSecs
                val reachedTop = blockChain!!.bestChainHeight >= peerVersionMessage!!.bestHeight
                if (!passedTime && !reachedTop) {
                    if (!isDownloadData) {
                        // Not download peer anymore, some other peer probably became better.
                        log.info("Lost download peer status, throwing away downloaded headers.")
                        return
                    }
                    if (blockChain.add(header)) {
                        // The block was successfully linked into the chain. Notify the user of our progress.
                        invokeOnBlocksDownloaded(header, null)
                    } else {
                        // This block is unconnected - we don't know how to get from it back to the genesis block yet.
                        // That must mean that the peer is buggy or malicious because we specifically requested for
                        // headers that are part of the best chain.
                        throw ProtocolException("Got unconnected header from peer: " + header.hashAsString)
                    }
                } else {
                    lock.lock()
                    try {
                        log.info(
                                "Passed the fast catchup time ({}) at height {}, discarding {} headers and requesting full blocks",
                                Utils.dateTimeFormat(fastCatchupTimeSecs * 1000), blockChain.bestChainHeight + 1,
                                m.blockHeaders!!.size - i)
                        this.downloadBlockBodies = true
                        // Prevent this request being seen as a duplicate.
                        this.lastGetBlocksBegin = Sha256Hash.ZERO_HASH
                        blockChainDownloadLocked(Sha256Hash.ZERO_HASH)
                    } finally {
                        lock.unlock()
                    }
                    return
                }
            }
            // We added all headers in the message to the chain. Request some more if we got up to the limit, otherwise
            // we are at the end of the chain.
            if (m.blockHeaders!!.size >= HeadersMessage.MAX_HEADERS) {
                lock.lock()
                try {
                    blockChainDownloadLocked(Sha256Hash.ZERO_HASH)
                } finally {
                    lock.unlock()
                }
            }
        } catch (e: VerificationException) {
            log.warn("Block header verification failed", e)
        } catch (e: PrunedException) {
            // Unreachable when in SPV mode.
            throw RuntimeException(e)
        }

    }

    protected fun processGetData(getdata: GetDataMessage) {
        log.info("{}: Received getdata message: {}", address, getdata.toString())
        val items = ArrayList<Message>()
        for (registration in getDataEventListeners) {
            if (registration.executor !== Threading.SAME_THREAD) continue
            val listenerItems = registration.listener.getData(this, getdata) ?: continue
            items.addAll(listenerItems)
        }
        if (items.isEmpty()) {
            return
        }
        log.info("{}: Sending {} items gathered from listeners to peer", address, items.size)
        for (item in items) {
            sendMessage(item)
        }
    }

    @Throws(VerificationException::class)
    protected fun processTransaction(tx: Transaction) {
        // Check a few basic syntax issues to ensure the received TX isn't nonsense.
        tx.verify()
        lock.lock()
        try {
            log.debug("{}: Received tx {}", address, tx.hashAsString)
            // Label the transaction as coming in from the P2P network (as opposed to being created by us, direct import,
            // etc). This helps the wallet decide how to risk analyze it later.
            //
            // Additionally, by invoking tx.getConfidence(), this tx now pins the confidence data into the heap, meaning
            // we can stop holding a reference to the confidence object ourselves. It's up to event listeners on the
            // Peer to stash the tx object somewhere if they want to keep receiving updates about network propagation
            // and so on.
            val confidence = tx.confidence
            confidence.source = TransactionConfidence.Source.NETWORK
            pendingTxDownloads.remove(confidence)
            if (maybeHandleRequestedData(tx)) {
                return
            }
            if (currentFilteredBlock != null) {
                if (!currentFilteredBlock!!.provideTransaction(tx)) {
                    // Got a tx that didn't fit into the filtered block, so we must have received everything.
                    endFilteredBlock(currentFilteredBlock)
                    currentFilteredBlock = null
                }
                // Don't tell wallets or listeners about this tx as they'll learn about it when the filtered block is
                // fully downloaded instead.
                return
            }
            // It's a broadcast transaction. Tell all wallets about this tx so they can check if it's relevant or not.
            for (wallet in wallets) {
                try {
                    if (wallet.isPendingTransactionRelevant(tx)) {
                        if (vDownloadTxDependencyDepth > 0) {
                            // This transaction seems interesting to us, so let's download its dependencies. This has
                            // several purposes: we can check that the sender isn't attacking us by engaging in protocol
                            // abuse games, like depending on a time-locked transaction that will never confirm, or
                            // building huge chains of unconfirmed transactions (again - so they don't confirm and the
                            // money can be taken back with a Finney attack). Knowing the dependencies also lets us
                            // store them in a serialized wallet so we always have enough data to re-announce to the
                            // network and get the payment into the chain, in case the sender goes away and the network
                            // starts to forget.
                            //
                            // TODO: Not all the above things are implemented.
                            //
                            // Note that downloading of dependencies can end up walking around 15 minutes back even
                            // through transactions that have confirmed, as getdata on the remote peer also checks
                            // relay memory not only the mempool. Unfortunately we have no way to know that here. In
                            // practice it should not matter much.
                            Futures.addCallback(downloadDependencies(tx), object : FutureCallback<List<Transaction>> {
                                override fun onSuccess(dependencies: List<Transaction>?) {
                                    try {
                                        log.info("{}: Dependency download complete!", address)
                                        wallet.receivePending(tx, dependencies)
                                    } catch (e: VerificationException) {
                                        log.error("{}: Wallet failed to process pending transaction {}", address, tx.hash)
                                        log.error("Error was: ", e)
                                        // Not much more we can do at this point.
                                    }

                                }

                                override fun onFailure(throwable: Throwable) {
                                    log.error("Could not download dependencies of tx {}", tx.hashAsString)
                                    log.error("Error was: ", throwable)
                                    // Not much more we can do at this point.
                                }
                            })
                        } else {
                            wallet.receivePending(tx, null)
                        }
                    }
                } catch (e: VerificationException) {
                    log.error("Wallet failed to verify tx", e)
                    // Carry on, listeners may still want to know.
                }

            }
        } finally {
            lock.unlock()
        }
        // Tell all listeners about this tx so they can decide whether to keep it or not. If no listener keeps a
        // reference around then the memory pool will forget about it after a while too because it uses weak references.
        for (registration in onTransactionEventListeners) {
            registration.executor.execute { registration.listener.onTransaction(this@Peer, tx) }
        }
    }

    /**
     *
     * Returns a future that wraps a list of all transactions that the given transaction depends on, recursively.
     * Only transactions in peers memory pools are included; the recursion stops at transactions that are in the
     * current best chain. So it doesn't make much sense to provide a tx that was already in the best chain and
     * a precondition checks this.
     *
     *
     * For example, if tx has 2 inputs that connect to transactions A and B, and transaction B is unconfirmed and
     * has one input connecting to transaction C that is unconfirmed, and transaction C connects to transaction D
     * that is in the chain, then this method will return either {B, C} or {C, B}. No ordering is guaranteed.
     *
     *
     * This method is useful for apps that want to learn about how long an unconfirmed transaction might take
     * to confirm, by checking for unexpectedly time locked transactions, unusually deep dependency trees or fee-paying
     * transactions that depend on unconfirmed free transactions.
     *
     *
     * Note that dependencies downloaded this way will not trigger the onTransaction method of event listeners.
     */
    fun downloadDependencies(tx: Transaction): ListenableFuture<List<Transaction>> {
        val txConfidence = tx.confidence.confidenceType
        Preconditions.checkArgument(txConfidence != TransactionConfidence.ConfidenceType.BUILDING)
        log.info("{}: Downloading dependencies of {}", address, tx.hashAsString)
        val results = LinkedList<Transaction>()
        // future will be invoked when the entire dependency tree has been walked and the results compiled.
        val future = downloadDependenciesInternal(vDownloadTxDependencyDepth, 0, tx,
                Any(), results)
        val resultFuture = SettableFuture.create<List<Transaction>>()
        Futures.addCallback(future, object : FutureCallback<Any> {
            override fun onSuccess(ignored: Any?) {
                resultFuture.set(results)
            }

            override fun onFailure(throwable: Throwable) {
                resultFuture.setException(throwable)
            }
        })
        return resultFuture
    }

    // The marker object in the future returned is the same as the parameter. It is arbitrary and can be anything.
    protected fun downloadDependenciesInternal(maxDepth: Int, depth: Int,
                                               tx: Transaction?, marker: Any, results: MutableList<Transaction>): ListenableFuture<Any> {

        val resultFuture = SettableFuture.create<Any>()
        val rootTxHash = tx!!.hash
        // We want to recursively grab its dependencies. This is so listeners can learn important information like
        // whether a transaction is dependent on a timelocked transaction or has an unexpectedly deep dependency tree
        // or depends on a no-fee transaction.

        // We may end up requesting transactions that we've already downloaded and thrown away here.
        val needToRequest = CopyOnWriteArraySet<Sha256Hash>()
        for (input in tx.inputs) {
            // There may be multiple inputs that connect to the same transaction.
            needToRequest.add(input.outpoint!!.hash)
        }
        lock.lock()
        try {
            // Build the request for the missing dependencies.
            val futures = Lists.newArrayList<ListenableFuture<Transaction>>()
            val getdata = GetDataMessage(params)
            if (needToRequest.size > 1)
                log.info("{}: Requesting {} transactions for depth {} dep resolution", address, needToRequest.size, depth + 1)
            for (hash in needToRequest) {
                getdata.addTransaction(hash)
                val req = GetDataRequest(hash, SettableFuture.create<Any>())
                futures.add(req.future)
                getDataFutures.add(req)
            }
            val successful = Futures.successfulAsList(futures)
            Futures.addCallback(successful, object : FutureCallback<List<Transaction>> {
                override fun onSuccess(transactions: List<Transaction>?) {
                    // Once all transactions either were received, or we know there are no more to come ...
                    // Note that transactions will contain "null" for any positions that weren't successful.
                    val childFutures = Lists.newLinkedList<ListenableFuture<Any>>()
                    for (tx in transactions!!) {
                        if (tx == null) continue
                        log.info("{}: Downloaded dependency of {}: {}", address, rootTxHash, tx.hashAsString)
                        results.add(tx)
                        // Now recurse into the dependencies of this transaction too.
                        if (depth + 1 < maxDepth)
                            childFutures.add(downloadDependenciesInternal(maxDepth, depth + 1, tx, marker, results))
                    }
                    if (childFutures.size == 0) {
                        // Short-circuit: we're at the bottom of this part of the tree.
                        resultFuture.set(marker)
                    } else {
                        // There are some children to download. Wait until it's done (and their children and their
                        // children...) to inform the caller that we're finished.
                        Futures.addCallback(Futures.successfulAsList(childFutures), object : FutureCallback<List<Any>> {
                            override fun onSuccess(objects: List<Any>?) {
                                resultFuture.set(marker)
                            }

                            override fun onFailure(throwable: Throwable) {
                                resultFuture.setException(throwable)
                            }
                        })
                    }
                }

                override fun onFailure(throwable: Throwable) {
                    resultFuture.setException(throwable)
                }
            })
            // Start the operation.
            sendMessage(getdata)
        } catch (e: Exception) {
            log.error("{}: Couldn't send getdata in downloadDependencies({})", this, tx.hash, e)
            resultFuture.setException(e)
            return resultFuture
        } finally {
            lock.unlock()
        }
        return resultFuture
    }

    protected fun processBlock(m: Block) {
        if (log.isDebugEnabled()) {
            log.debug("{}: Received broadcast block {}", address, m.hashAsString)
        }
        // Was this block requested by getBlock()?
        if (maybeHandleRequestedData(m)) return
        if (blockChain == null) {
            log.debug("Received block but was not configured with an AbstractBlockChain")
            return
        }
        // Did we lose download peer status after requesting block data?
        if (!isDownloadData) {
            log.debug("{}: Received block we did not ask for: {}", address, m.hashAsString)
            return
        }
        pendingBlockDownloads.remove(m.hash)
        try {
            // Otherwise it's a block sent to us because the peer thought we needed it, so add it to the block chain.
            if (blockChain.add(m)) {
                // The block was successfully linked into the chain. Notify the user of our progress.
                invokeOnBlocksDownloaded(m, null)
            } else {
                // This block is an orphan - we don't know how to get from it back to the genesis block yet. That
                // must mean that there are blocks we are missing, so do another getblocks with a new block locator
                // to ask the peer to send them to us. This can happen during the initial block chain download where
                // the peer will only send us 500 at a time and then sends us the head block expecting us to request
                // the others.
                //
                // We must do two things here:
                // (1) Request from current top of chain to the oldest ancestor of the received block in the orphan set
                // (2) Filter out duplicate getblock requests (done in blockChainDownloadLocked).
                //
                // The reason for (1) is that otherwise if new blocks were solved during the middle of chain download
                // we'd do a blockChainDownloadLocked() on the new best chain head, which would cause us to try and grab the
                // chain twice (or more!) on the same connection! The block chain would filter out the duplicates but
                // only at a huge speed penalty. By finding the orphan root we ensure every getblocks looks the same
                // no matter how many blocks are solved, and therefore that the (2) duplicate filtering can work.
                //
                // We only do this if we are not currently downloading headers. If we are then we don't want to kick
                // off a request for lots more headers in parallel.
                lock.lock()
                try {
                    if (downloadBlockBodies) {
                        val orphanRoot = checkNotNull<Block>(blockChain.getOrphanRoot(m.hash))
                        blockChainDownloadLocked(orphanRoot.hash)
                    } else {
                        log.info("Did not start chain download on solved block due to in-flight header download.")
                    }
                } finally {
                    lock.unlock()
                }
            }
        } catch (e: VerificationException) {
            // We don't want verification failures to kill the thread.
            log.warn("{}: Block verification failed", address, e)
        } catch (e: PrunedException) {
            // Unreachable when in SPV mode.
            throw RuntimeException(e)
        }

    }

    // TODO: Fix this duplication.
    protected fun endFilteredBlock(m: FilteredBlock) {
        if (log.isDebugEnabled())
            log.debug("{}: Received broadcast filtered block {}", address, m.hash.toString())
        if (!isDownloadData) {
            log.debug("{}: Received block we did not ask for: {}", address, m.hash.toString())
            return
        }
        if (blockChain == null) {
            log.debug("Received filtered block but was not configured with an AbstractBlockChain")
            return
        }
        // Note that we currently do nothing about peers which maliciously do not include transactions which
        // actually match our filter or which simply do not send us all the transactions we need: it can be fixed
        // by cross-checking peers against each other.
        pendingBlockDownloads.remove(m.blockHeader.hash)
        try {
            // It's a block sent to us because the peer thought we needed it, so maybe add it to the block chain.
            // The FilteredBlock m here contains a list of hashes, and may contain Transaction objects for a subset
            // of the hashes (those that were sent to us by the remote peer). Any hashes that haven't had a tx
            // provided in processTransaction are ones that were announced to us previously via an 'inv' so the
            // assumption is we have already downloaded them and either put them in the wallet, or threw them away
            // for being false positives.
            //
            // TODO: Fix the following protocol race.
            // It is possible for this code to go wrong such that we miss a confirmation. If the remote peer announces
            // a relevant transaction via an 'inv' and then it immediately announces the block that confirms
            // the tx before we had a chance to download it+its dependencies and provide them to the wallet, then we
            // will add the block to the chain here without the tx being in the wallet and thus it will miss its
            // confirmation and become stuck forever. The fix is to notice that there's a pending getdata for a tx
            // that appeared in this block and delay processing until it arrived ... it's complicated by the fact that
            // the data may be requested by a different peer to this one.

            // Ask each wallet attached to the peer/blockchain if this block exhausts the list of data items
            // (keys/addresses) that were used to calculate the previous filter. If so, then it's possible this block
            // is only partial. Check for discarding first so we don't check for exhaustion on blocks we already know
            // we're going to discard, otherwise redundant filters might end up being queued and calculated.
            lock.lock()
            try {
                if (awaitingFreshFilter != null) {
                    log.info("Discarding block {} because we're still waiting for a fresh filter", m.hash)
                    // We must record the hashes of blocks we discard because you cannot do getblocks twice on the same
                    // range of blocks and get an inv both times, due to the codepath in Bitcoin Core hitting
                    // CPeer::PushInventory() which checks CPeer::setInventoryKnown and thus deduplicates.
                    awaitingFreshFilter!!.add(m.hash)
                    return    // Chain download process is restarted via a call to setBloomFilter.
                } else if (checkForFilterExhaustion(m)) {
                    // Yes, so we must abandon the attempt to process this block and any further blocks we receive,
                    // then wait for the Bloom filter to be recalculated, sent to this peer and for the peer to acknowledge
                    // that the new filter is now in use (which we have to simulate with a ping/pong), and then we can
                    // safely restart the chain download with the new filter that contains a new set of lookahead keys.
                    log.info("Bloom filter exhausted whilst processing block {}, discarding", m.hash)
                    awaitingFreshFilter = LinkedList()
                    awaitingFreshFilter!!.add(m.hash)
                    awaitingFreshFilter!!.addAll(blockChain.drainOrphanBlocks())
                    return    // Chain download process is restarted via a call to setBloomFilter.
                }
            } finally {
                lock.unlock()
            }

            if (blockChain.add(m)) {
                // The block was successfully linked into the chain. Notify the user of our progress.
                invokeOnBlocksDownloaded(m.blockHeader, m)
            } else {
                // This block is an orphan - we don't know how to get from it back to the genesis block yet. That
                // must mean that there are blocks we are missing, so do another getblocks with a new block locator
                // to ask the peer to send them to us. This can happen during the initial block chain download where
                // the peer will only send us 500 at a time and then sends us the head block expecting us to request
                // the others.
                //
                // We must do two things here:
                // (1) Request from current top of chain to the oldest ancestor of the received block in the orphan set
                // (2) Filter out duplicate getblock requests (done in blockChainDownloadLocked).
                //
                // The reason for (1) is that otherwise if new blocks were solved during the middle of chain download
                // we'd do a blockChainDownloadLocked() on the new best chain head, which would cause us to try and grab the
                // chain twice (or more!) on the same connection! The block chain would filter out the duplicates but
                // only at a huge speed penalty. By finding the orphan root we ensure every getblocks looks the same
                // no matter how many blocks are solved, and therefore that the (2) duplicate filtering can work.
                lock.lock()
                try {
                    val orphanRoot = checkNotNull<Block>(blockChain.getOrphanRoot(m.hash))
                    blockChainDownloadLocked(orphanRoot.hash)
                } finally {
                    lock.unlock()
                }
            }
        } catch (e: VerificationException) {
            // We don't want verification failures to kill the thread.
            log.warn("{}: FilteredBlock verification failed", address, e)
        } catch (e: PrunedException) {
            // We pruned away some of the data we need to properly handle this block. We need to request the needed
            // data from the remote peer and fix things. Or just give up.
            // TODO: Request e.getHash() and submit it to the block store before any other blocks
            throw RuntimeException(e)
        }

    }

    private fun checkForFilterExhaustion(m: FilteredBlock): Boolean {
        var exhausted = false
        for (wallet in wallets) {
            exhausted = exhausted or wallet.checkForFilterExhaustion(m)
        }
        return exhausted
    }

    private fun maybeHandleRequestedData(m: Message): Boolean {
        var found = false
        val hash = m.hash
        for (req in getDataFutures) {
            if (hash == req.hash) {
                req.future.set(m)
                getDataFutures.remove(req)
                found = true
                // Keep going in case there are more.
            }
        }
        return found
    }

    private fun invokeOnBlocksDownloaded(block: Block, fb: FilteredBlock?) {
        // It is possible for the peer block height difference to be negative when blocks have been solved and broadcast
        // since the time we first connected to the peer. However, it's weird and unexpected to receive a callback
        // with negative "blocks left" in this case, so we clamp to zero so the API user doesn't have to think about it.
        val blocksLeft = Math.max(0, peerVersionMessage!!.bestHeight.toInt() - checkNotNull<AbstractBlockChain>(blockChain).bestChainHeight)
        for (registration in blocksDownloadedEventListeners) {
            registration.executor.execute { registration.listener.onBlocksDownloaded(this@Peer, block, fb, blocksLeft) }
        }
    }

    protected fun processInv(inv: InventoryMessage) {
        val items = inv.getItems()

        // Separate out the blocks and transactions, we'll handle them differently
        val transactions = LinkedList<InventoryItem>()
        val blocks = LinkedList<InventoryItem>()

        for (item in items) {
            when (item.type) {
                InventoryItem.Type.Transaction -> transactions.add(item)
                InventoryItem.Type.Block -> blocks.add(item)
                else -> throw IllegalStateException("Not implemented: " + item.type)
            }
        }

        val downloadData = this.isDownloadData

        if (transactions.size == 0 && blocks.size == 1) {
            // Single block announcement. If we're downloading the chain this is just a tickle to make us continue
            // (the block chain download protocol is very implicit and not well thought out). If we're not downloading
            // the chain then this probably means a new block was solved and the peer believes it connects to the best
            // chain, so count it. This way getBestChainHeight() can be accurate.
            if (downloadData && blockChain != null) {
                if (!blockChain.isOrphan(blocks[0].hash)) {
                    blocksAnnounced.incrementAndGet()
                }
            } else {
                blocksAnnounced.incrementAndGet()
            }
        }

        val getdata = GetDataMessage(params)

        val it = transactions.iterator()
        while (it.hasNext()) {
            val item = it.next()
            // Only download the transaction if we are the first peer that saw it be advertised. Other peers will also
            // see it be advertised in inv packets asynchronously, they co-ordinate via the memory pool. We could
            // potentially download transactions faster by always asking every peer for a tx when advertised, as remote
            // peers run at different speeds. However to conserve bandwidth on mobile devices we try to only download a
            // transaction once. This means we can miss broadcasts if the peer disconnects between sending us an inv and
            // sending us the transaction: currently we'll never try to re-fetch after a timeout.
            //
            // The line below can trigger confidence listeners.
            val conf = context!!.confidenceTable.seen(item.hash, this.address)
            if (conf.numBroadcastPeers() > 1) {
                // Some other peer already announced this so don't download.
                it.remove()
            } else if (conf.source == TransactionConfidence.Source.SELF) {
                // We created this transaction ourselves, so don't download.
                it.remove()
            } else {
                log.debug("{}: getdata on tx {}", address, item.hash)
                getdata.addItem(item)
                // Register with the garbage collector that we care about the confidence data for a while.
                pendingTxDownloads.add(conf)
            }
        }

        // If we are requesting filteredblocks we have to send a ping after the getdata so that we have a clear
        // end to the final FilteredBlock's transactions (in the form of a pong) sent to us
        var pingAfterGetData = false

        lock.lock()
        try {
            if (blocks.size > 0 && downloadData && blockChain != null) {
                // Ideally, we'd only ask for the data here if we actually needed it. However that can imply a lot of
                // disk IO to figure out what we've got. Normally peers will not send us inv for things we already have
                // so we just re-request it here, and if we get duplicates the block chain / wallet will filter them out.
                for (item in blocks) {
                    if (blockChain.isOrphan(item.hash) && downloadBlockBodies) {
                        // If an orphan was re-advertised, ask for more blocks unless we are not currently downloading
                        // full block data because we have a getheaders outstanding.
                        val orphanRoot = checkNotNull<Block>(blockChain.getOrphanRoot(item.hash))
                        blockChainDownloadLocked(orphanRoot.hash)
                    } else {
                        // Don't re-request blocks we already requested. Normally this should not happen. However there is
                        // an edge case: if a block is solved and we complete the inv<->getdata<->block<->getblocks cycle
                        // whilst other parts of the chain are streaming in, then the new getblocks request won't match the
                        // previous one: whilst the stopHash is the same (because we use the orphan root), the start hash
                        // will be different and so the getblocks req won't be dropped as a duplicate. We'll end up
                        // requesting a subset of what we already requested, which can lead to parallel chain downloads
                        // and other nastyness. So we just do a quick removal of redundant getdatas here too.
                        //
                        // Note that as of June 2012 Bitcoin Core won't actually ever interleave blocks pushed as
                        // part of chain download with newly announced blocks, so it should always be taken care of by
                        // the duplicate check in blockChainDownloadLocked(). But Bitcoin Core may change in future so
                        // it's better to be safe here.
                        if (!pendingBlockDownloads.contains(item.hash)) {
                            if (peerVersionMessage!!.isBloomFilteringSupported && useFilteredBlocks) {
                                getdata.addFilteredBlock(item.hash)
                                pingAfterGetData = true
                            } else {
                                getdata.addItem(item)
                            }
                            pendingBlockDownloads.add(item.hash)
                        }
                    }
                }
                // If we're downloading the chain, doing a getdata on the last block we were told about will cause the
                // peer to advertize the head block to us in a single-item inv. When we download THAT, it will be an
                // orphan block, meaning we'll re-enter blockChainDownloadLocked() to trigger another getblocks between the
                // current best block we have and the orphan block. If more blocks arrive in the meantime they'll also
                // become orphan.
            }
        } finally {
            lock.unlock()
        }

        if (!getdata.getItems().isEmpty()) {
            // This will cause us to receive a bunch of block or tx messages.
            sendMessage(getdata)
        }

        if (pingAfterGetData)
            sendMessage(Ping((Math.random() * java.lang.Long.MAX_VALUE).toLong()))
    }

    /**
     * Asks the connected peer for the block of the given hash, and returns a future representing the answer.
     * If you want the block right away and don't mind waiting for it, just call .get() on the result. Your thread
     * will block until the peer answers.
     */
    // The 'unchecked conversion' warning being suppressed here comes from the sendSingleGetData() formally returning
    // ListenableFuture instead of ListenableFuture<Block>. This is okay as sendSingleGetData() actually returns
    // ListenableFuture<Block> in this context. Note that sendSingleGetData() is also used for Transactions.
    fun getBlock(blockHash: Sha256Hash): ListenableFuture<Block> {
        // This does not need to be locked.
        log.info("Request to fetch block {}", blockHash)
        val getdata = GetDataMessage(params)
        getdata.addBlock(blockHash)
        return sendSingleGetData(getdata)
    }

    /**
     * Asks the connected peer for the given transaction from its memory pool. Transactions in the chain cannot be
     * retrieved this way because peers don't have a transaction ID to transaction-pos-on-disk index, and besides,
     * in future many peers will delete old transaction data they don't need.
     */
    // The 'unchecked conversion' warning being suppressed here comes from the sendSingleGetData() formally returning
    // ListenableFuture instead of ListenableFuture<Transaction>. This is okay as sendSingleGetData() actually returns
    // ListenableFuture<Transaction> in this context. Note that sendSingleGetData() is also used for Blocks.
    fun getPeerMempoolTransaction(hash: Sha256Hash): ListenableFuture<Transaction> {
        // This does not need to be locked.
        // TODO: Unit test this method.
        log.info("Request to fetch peer mempool tx  {}", hash)
        val getdata = GetDataMessage(params)
        getdata.addTransaction(hash)
        return sendSingleGetData(getdata)
    }

    /** Sends a getdata with a single item in it.  */
    private fun sendSingleGetData(getdata: GetDataMessage): ListenableFuture<*> {
        // This does not need to be locked.
        Preconditions.checkArgument(getdata.getItems().size == 1)
        val req = GetDataRequest(getdata.getItems()[0].hash, SettableFuture.create<Any>())
        getDataFutures.add(req)
        sendMessage(getdata)
        return req.future
    }

    /**
     * When downloading the block chain, the bodies will be skipped for blocks created before the given date. Any
     * transactions relevant to the wallet will therefore not be found, but if you know your wallet has no such
     * transactions it doesn't matter and can save a lot of bandwidth and processing time. Note that the times of blocks
     * isn't known until their headers are available and they are requested in chunks, so some headers may be downloaded
     * twice using this scheme, but this optimization can still be a large win for newly created wallets.
     *
     * @param secondsSinceEpoch Time in seconds since the epoch or 0 to reset to always downloading block bodies.
     */
    fun setDownloadParameters(secondsSinceEpoch: Long, useFilteredBlocks: Boolean) {
        lock.lock()
        try {
            if (secondsSinceEpoch == 0L) {
                fastCatchupTimeSecs = params.genesisBlock.timeSeconds
                downloadBlockBodies = true
            } else {
                fastCatchupTimeSecs = secondsSinceEpoch
                // If the given time is before the current chains head block time, then this has no effect (we already
                // downloaded everything we need).
                if (blockChain != null && fastCatchupTimeSecs > blockChain.getChainHead().header.timeSeconds)
                    downloadBlockBodies = false
            }
            this.useFilteredBlocks = useFilteredBlocks
        } finally {
            lock.unlock()
        }
    }

    /**
     * Links the given wallet to this peer. If you have multiple peers, you should use a [PeerGroup] to manage
     * them and use the [PeerGroup.addWallet] method instead of registering the wallet with each peer
     * independently, otherwise the wallet will receive duplicate notifications.
     */
    fun addWallet(wallet: Wallet) {
        wallets.add(wallet)
    }

    /** Unlinks the given wallet from peer. See [Peer.addWallet].  */
    fun removeWallet(wallet: Wallet) {
        wallets.remove(wallet)
    }

    @GuardedBy("lock")
    private fun blockChainDownloadLocked(toHash: Sha256Hash) {
        checkState(lock.isHeldByCurrentThread)
        // The block chain download process is a bit complicated. Basically, we start with one or more blocks in a
        // chain that we have from a previous session. We want to catch up to the head of the chain BUT we don't know
        // where that chain is up to or even if the top block we have is even still in the chain - we
        // might have got ourselves onto a fork that was later resolved by the network.
        //
        // To solve this, we send the peer a block locator which is just a list of block hashes. It contains the
        // blocks we know about, but not all of them, just enough of them so the peer can figure out if we did end up
        // on a fork and if so, what the earliest still valid block we know about is likely to be.
        //
        // Once it has decided which blocks we need, it will send us an inv with up to 500 block messages. We may
        // have some of them already if we already have a block chain and just need to catch up. Once we request the
        // last block, if there are still more to come it sends us an "inv" containing only the hash of the head
        // block.
        //
        // That causes us to download the head block but then we find (in processBlock) that we can't connect
        // it to the chain yet because we don't have the intermediate blocks. So we rerun this function building a
        // new block locator describing where we're up to.
        //
        // The getblocks with the new locator gets us another inv with another bunch of blocks. We download them once
        // again. This time when the peer sends us an inv with the head block, we already have it so we won't download
        // it again - but we recognize this case as special and call back into blockChainDownloadLocked to continue the
        // process.
        //
        // So this is a complicated process but it has the advantage that we can download a chain of enormous length
        // in a relatively stateless manner and with constant memory usage.
        //
        // All this is made more complicated by the desire to skip downloading the bodies of blocks that pre-date the
        // 'fast catchup time', which is usually set to the creation date of the earliest key in the wallet. Because
        // we know there are no transactions using our keys before that date, we need only the headers. To do that we
        // use the "getheaders" command. Once we find we've gone past the target date, we throw away the downloaded
        // headers and then request the blocks from that point onwards. "getheaders" does not send us an inv, it just
        // sends us the data we requested in a "headers" message.

        // TODO: Block locators should be abstracted out rather than special cased here.
        val blockLocator = ArrayList<Sha256Hash>(51)
        // For now we don't do the exponential thinning as suggested here:
        //
        //   https://en.bitcoin.it/wiki/Protocol_specification#getblocks
        //
        // This is because it requires scanning all the block chain headers, which is very slow. Instead we add the top
        // 100 block headers. If there is a re-org deeper than that, we'll end up downloading the entire chain. We
        // must always put the genesis block as the first entry.
        val store = checkNotNull<AbstractBlockChain>(blockChain).blockStore
        val chainHead = blockChain!!.getChainHead()
        val chainHeadHash = chainHead.header.hash
        // Did we already make this request? If so, don't do it again.
        if (Objects.equal(lastGetBlocksBegin, chainHeadHash) && Objects.equal(lastGetBlocksEnd, toHash)) {
            log.info("blockChainDownloadLocked({}): ignoring duplicated request: {}", toHash, chainHeadHash)
            for (hash in pendingBlockDownloads)
                log.info("Pending block download: {}", hash)
            log.info(Throwables.getStackTraceAsString(Throwable()))
            return
        }
        if (log.isDebugEnabled())
            log.debug("{}: blockChainDownloadLocked({}) current head = {}",
                    this, toHash, chainHead.header.hashAsString)
        var cursor: StoredBlock? = chainHead
        var i = 100
        while (cursor != null && i > 0) {
            blockLocator.add(cursor.header.hash)
            try {
                cursor = cursor.getPrev(store)
            } catch (e: BlockStoreException) {
                log.error("Failed to walk the block chain whilst constructing a locator")
                throw RuntimeException(e)
            }

            i--
        }
        // Only add the locator if we didn't already do so. If the chain is < 50 blocks we already reached it.
        if (cursor != null)
            blockLocator.add(params.genesisBlock.hash)

        // Record that we requested this range of blocks so we can filter out duplicate requests in the event of a
        // block being solved during chain download.
        lastGetBlocksBegin = chainHeadHash
        lastGetBlocksEnd = toHash

        if (downloadBlockBodies) {
            val message = GetBlocksMessage(params, blockLocator, toHash)
            sendMessage(message)
        } else {
            // Downloading headers for a while instead of full blocks.
            val message = GetHeadersMessage(params, blockLocator, toHash)
            sendMessage(message)
        }
    }

    /**
     * Starts an asynchronous download of the block chain. The chain download is deemed to be complete once we've
     * downloaded the same number of blocks that the peer advertised having in its version handshake message.
     */
    fun startBlockChainDownload() {
        isDownloadData = true
        // TODO: peer might still have blocks that we don't have, and even have a heavier
        // chain even if the chain block count is lower.
        val blocksLeft = peerBlockHeightDifference
        if (blocksLeft >= 0) {
            for (registration in chainDownloadStartedEventListeners) {
                registration.executor.execute { registration.listener.onChainDownloadStarted(this@Peer, blocksLeft) }
            }
            // When we just want as many blocks as possible, we can set the target hash to zero.
            lock.lock()
            try {
                blockChainDownloadLocked(Sha256Hash.ZERO_HASH)
            } finally {
                lock.unlock()
            }
        }
    }

    private inner class PendingPing(// The random nonce that lets us tell apart overlapping pings/pongs.
            val nonce: Long) {
        // The future that will be invoked when the pong is heard back.
        var future: SettableFuture<Long>
        // Measurement of the time elapsed.
        val startTimeMsec: Long

        init {
            future = SettableFuture.create()
            startTimeMsec = Utils.currentTimeMillis()
        }

        fun complete() {
            if (!future.isDone) {
                val elapsed = Utils.currentTimeMillis() - startTimeMsec
                this@Peer.addPingTimeData(elapsed)
                log.debug("{}: ping time is {} msec", this@Peer.toString(), elapsed)
                future.set(elapsed)
            }
        }
    }

    /** Adds a ping time sample to the averaging window.  */
    private fun addPingTimeData(sample: Long) {
        lastPingTimesLock.lock()
        try {
            if (lastPingTimes == null) {
                lastPingTimes = LongArray(PING_MOVING_AVERAGE_WINDOW)
                // Initialize the averaging window to the first sample.
                Arrays.fill(lastPingTimes!!, sample)
            } else {
                // Shift all elements backwards by one.
                System.arraycopy(lastPingTimes!!, 1, lastPingTimes!!, 0, lastPingTimes!!.size - 1)
                // And append the new sample to the end.
                lastPingTimes[lastPingTimes!!.size - 1] = sample
            }
        } finally {
            lastPingTimesLock.unlock()
        }
    }

    /**
     * Sends the peer a ping message and returns a future that will be invoked when the pong is received back.
     * The future provides a number which is the number of milliseconds elapsed between the ping and the pong.
     * Once the pong is received the value returned by [org.bitcoinj.core.Peer.getLastPingTime] is
     * updated.
     * @throws ProtocolException if the peer version is too low to support measurable pings.
     */
    @Throws(ProtocolException::class)
    fun ping(): ListenableFuture<Long> {
        return ping((Math.random() * java.lang.Long.MAX_VALUE).toLong())
    }

    @Throws(ProtocolException::class)
    protected fun ping(nonce: Long): ListenableFuture<Long> {
        val ver = peerVersionMessage
        if (!ver!!.isPingPongSupported)
            throw ProtocolException("Peer version is too low for measurable pings: " + ver)
        val pendingPing = PendingPing(nonce)
        pendingPings.add(pendingPing)
        sendMessage(Ping(pendingPing.nonce))
        return pendingPing.future
    }

    private fun processPing(m: Ping) {
        if (m.hasNonce())
            sendMessage(Pong(m.nonce))
    }

    protected fun processPong(m: Pong) {
        // Iterates over a snapshot of the list, so we can run unlocked here.
        for (ping in pendingPings) {
            if (m.nonce == ping.nonce) {
                pendingPings.remove(ping)
                // This line may trigger an event listener that re-runs ping().
                ping.complete()
                return
            }
        }
    }

    /**
     * The minimum P2P protocol version that is accepted. If the peer speaks a protocol version lower than this, it
     * will be disconnected.
     * @return true if the peer was disconnected as a result
     */
    fun setMinProtocolVersion(minProtocolVersion: Int): Boolean {
        this.vMinProtocolVersion = minProtocolVersion
        val ver = peerVersionMessage
        if (ver != null && ver.clientVersion < minProtocolVersion) {
            log.warn("{}: Disconnecting due to new min protocol version {}, got: {}", this, minProtocolVersion, ver.clientVersion)
            close()
            return true
        }
        return false
    }

    /**
     *
     * Sets a Bloom filter on this connection. This will cause the given [BloomFilter] object to be sent to the
     * remote peer and if requested, a [MemoryPoolMessage] is sent as well to trigger downloading of any
     * pending transactions that may be relevant.
     *
     *
     * The Peer does not automatically request filters from any wallets added using [Peer.addWallet].
     * This is to allow callers to avoid redundantly recalculating the same filter repeatedly when using multiple peers
     * and multiple wallets together.
     *
     *
     * Therefore, you should not use this method if your app uses a [PeerGroup]. It is called for you.
     *
     *
     * If the remote peer doesn't support Bloom filtering, then this call is ignored. Once set you presently cannot
     * unset a filter, though the underlying p2p protocol does support it.
     */
    fun setBloomFilter(filter: BloomFilter, andQueryMemPool: Boolean) {
        checkNotNull(filter, "Clearing filters is not currently supported")
        val ver = peerVersionMessage
        if (ver == null || !ver.isBloomFilteringSupported)
            return
        vBloomFilter = filter
        log.debug("{}: Sending Bloom filter{}", this, if (andQueryMemPool) " and querying mempool" else "")
        sendMessage(filter)
        if (andQueryMemPool)
            sendMessage(MemoryPoolMessage())
        maybeRestartChainDownload()
    }

    private fun maybeRestartChainDownload() {
        lock.lock()
        try {
            if (awaitingFreshFilter == null)
                return
            if (!isDownloadData) {
                // This branch should be harmless but I want to know how often it happens in reality.
                log.warn("Lost download peer status whilst awaiting fresh filter.")
                return
            }
            // Ping/pong to wait for blocks that are still being streamed to us to finish being downloaded and
            // discarded.
            ping().addListener(Runnable {
                lock.lock()
                checkNotNull<List<Sha256Hash>>(awaitingFreshFilter)
                val getdata = GetDataMessage(params)
                for (hash in awaitingFreshFilter!!)
                    getdata.addFilteredBlock(hash)
                awaitingFreshFilter = null
                lock.unlock()

                log.info("Restarting chain download")
                sendMessage(getdata)
                // TODO: This bizarre ping-after-getdata hack probably isn't necessary.
                // It's to ensure we know when the end of a filtered block stream of txns is, but we should just be
                // able to match txns with the merkleblock. Ask Matt why it's written this way.
                sendMessage(Ping((Math.random() * java.lang.Long.MAX_VALUE).toLong()))
            }, Threading.SAME_THREAD)
        } finally {
            lock.unlock()
        }
    }

    /**
     * Sends a query to the remote peer asking for the unspent transaction outputs (UTXOs) for the given outpoints.
     * The result should be treated only as a hint: it's possible for the returned outputs to be fictional and not
     * exist in any transaction, and it's possible for them to be spent the moment after the query returns.
     * **Most peers do not support this request. You will need to connect to Bitcoin XT peers if you want
     * this to work.**
     *
     * @param includeMempool If true (the default) the results take into account the contents of the memory pool too.
     * @throws ProtocolException if this peer doesn't support the protocol.
     */
    @JvmOverloads
    fun getUTXOs(outPoints: List<TransactionOutPoint>, includeMempool: Boolean = true): ListenableFuture<UTXOsMessage> {
        lock.lock()
        try {
            val peerVer = peerVersionMessage
            if (peerVer!!.clientVersion < GetUTXOsMessage.MIN_PROTOCOL_VERSION)
                throw ProtocolException("Peer does not support getutxos protocol version")
            if (peerVer.localServices and GetUTXOsMessage.SERVICE_FLAGS_REQUIRED != GetUTXOsMessage.SERVICE_FLAGS_REQUIRED)
                throw ProtocolException("Peer does not support getutxos protocol flag: find Bitcoin XT nodes.")
            val future = SettableFuture.create<UTXOsMessage>()
            // Add to the list of in flight requests.
            if (getutxoFutures == null)
                getutxoFutures = LinkedList()
            getutxoFutures!!.add(future)
            sendMessage(GetUTXOsMessage(params, outPoints, includeMempool))
            return future
        } finally {
            lock.unlock()
        }
    }

    /**
     * Sets if this peer will use getdata/notfound messages to walk backwards through transaction dependencies
     * before handing the transaction off to the wallet. The wallet can do risk analysis on pending/recent transactions
     * to try and discover if a pending tx might be at risk of double spending.
     */
    fun setDownloadTxDependencies(depth: Int) {
        vDownloadTxDependencyDepth = depth
    }

    companion object {
        private val log = LoggerFactory.getLogger(Peer::class.java!!)
        // How frequently to refresh the filter. This should become dynamic in future and calculated depending on the
        // actual false positive rate. For now a good value was determined empirically around January 2013.
        private val RESEND_BLOOM_FILTER_BLOCK_COUNT = 25000
        private val PING_MOVING_AVERAGE_WINDOW = 20
    }
}
/**
 *
 * Construct a peer that reads/writes from the given block chain. Transactions stored in a [org.bitcoinj.core.TxConfidenceTable]
 * will have their confidence levels updated when a peer announces it, to reflect the greater likelyhood that
 * the transaction is valid.
 *
 *
 * Note that this does **NOT** make a connection to the given remoteAddress, it only creates a handler for a
 * connection. If you want to create a one-off connection, create a Peer and pass it to
 * [org.bitcoinj.net.NioClientManager.openConnection]
 * or
 * [org.bitcoinj.net.NioClient.NioClient].
 *
 *
 * The remoteAddress provided should match the remote address of the peer which is being connected to, and is
 * used to keep track of which peers relayed transactions and offer more descriptive logging.
 */
/**
 * Sends a query to the remote peer asking for the unspent transaction outputs (UTXOs) for the given outpoints,
 * with the memory pool included. The result should be treated only as a hint: it's possible for the returned
 * outputs to be fictional and not exist in any transaction, and it's possible for them to be spent the moment
 * after the query returns. **Most peers do not support this request. You will need to connect to Bitcoin XT
 * peers if you want this to work.**
 *
 * @throws ProtocolException if this peer doesn't support the protocol.
 */
