/*
 * Copyright 2013 Google Inc.
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

import com.google.common.annotations.*
import com.google.common.base.*
import com.google.common.collect.*
import com.google.common.net.*
import com.google.common.primitives.*
import com.google.common.util.concurrent.*
import com.squareup.okhttp.*
import com.subgraph.orchid.*
import net.jcip.annotations.*
import org.bitcoinj.core.listeners.*
import org.bitcoinj.crypto.*
import org.bitcoinj.net.*
import org.bitcoinj.net.discovery.*
import org.bitcoinj.script.*
import org.bitcoinj.utils.*
import org.bitcoinj.utils.Threading
import org.bitcoinj.wallet.Wallet
import org.bitcoinj.wallet.listeners.KeyChainEventListener
import org.bitcoinj.wallet.listeners.ScriptsChangeEventListener
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener
import org.slf4j.*

import javax.annotation.*
import java.io.*
import java.net.*
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.locks.*

import com.google.common.base.Preconditions.*

/**
 *
 * Runs a set of connections to the P2P network, brings up connections to replace disconnected nodes and manages
 * the interaction between them all. Most applications will want to use one of these.
 *
 *
 * PeerGroup tries to maintain a constant number of connections to a set of distinct peers.
 * Each peer runs a network listener in its own thread.  When a connection is lost, a new peer
 * will be tried after a delay as long as the number of connections less than the maximum.
 *
 *
 * Connections are made to addresses from a provided list.  When that list is exhausted,
 * we start again from the head of the list.
 *
 *
 * The PeerGroup can broadcast a transaction to the currently connected set of peers.  It can
 * also handle download of the blockchain from peers, restarting the process when peers die.
 *
 *
 * A PeerGroup won't do anything until you call the [PeerGroup.start] method
 * which will block until peer discovery is completed and some outbound connections
 * have been initiated (it will return before handshaking is done, however).
 * You should call [PeerGroup.stop] when finished. Note that not all methods
 * of PeerGroup are safe to call from a UI thread as some may do network IO,
 * but starting and stopping the service should be fine.
 */
open class PeerGroup
/**
 * Creates a new PeerGroup allowing you to specify the [ClientConnectionManager] which is used to create new
 * connections and keep track of existing ones.
 */
private constructor(context: Context, protected val chain: AbstractBlockChain?, private val channels: ClientConnectionManager,
                    /**
                     * Returns the [com.subgraph.orchid.TorClient] object for this peer group, if Tor is in use, null otherwise.
                     */
                    val torClient: TorClient?) : TransactionBroadcaster {

    // All members in this class should be marked with final, volatile, @GuardedBy or a mix as appropriate to define
    // their thread safety semantics. Volatile requires a Hungarian-style v prefix.

    // By default we don't require any services because any peer will do.
    private var requiredServices: Long = 0
    /**
     * Returns the maximum number of [Peer]s to discover. This maximum is checked after
     * each [PeerDiscovery] so this max number can be surpassed.
     * @return the maximum number of peers to discover
     */
    /**
     * Sets the maximum number of [Peer]s to discover. This maximum is checked after
     * each [PeerDiscovery] so this max number can be surpassed.
     * @param maxPeersToDiscoverCount the maximum number of peers to discover
     */
    @Volatile
    var maxPeersToDiscoverCount = 100
    @Volatile private var vPeerDiscoveryTimeoutMillis = DEFAULT_PEER_DISCOVERY_TIMEOUT_MILLIS

    protected val lock = Threading.lock("peergroup")

    protected val params: NetworkParameters

    // This executor is used to queue up jobs: it's used when we don't want to use locks for mutual exclusion,
    // typically because the job might call in to user provided code that needs/wants the freedom to use the API
    // however it wants, or because a job needs to be ordered relative to other jobs like that.
    protected val executor: ListeningScheduledExecutorService

    // Whether the peer group is currently running. Once shut down it cannot be restarted.
    @Volatile
    var isRunning: Boolean = false
        private set
    // Whether the peer group has been started or not. An unstarted PG does not try to access the network.
    @Volatile private var vUsedUp: Boolean = false

    // Addresses to try to connect to, excluding active peers.
    @GuardedBy("lock") private val inactives: PriorityQueue<PeerAddress>
    @GuardedBy("lock") private val backoffMap: MutableMap<PeerAddress, ExponentialBackoff>

    // Currently active peers. This is an ordered list rather than a set to make unit tests predictable.
    private val peers: CopyOnWriteArrayList<Peer>
    // Currently connecting peers.
    private val pendingPeers: CopyOnWriteArrayList<Peer>

    // The peer that has been selected for the purposes of downloading announced data.
    @GuardedBy("lock") private var downloadPeer: Peer? = null
    // Callback for events related to chain download.
    @GuardedBy("lock") private var downloadListener: PeerDataEventListener? = null
    private val peersBlocksDownloadedEventListeners = CopyOnWriteArrayList<ListenerRegistration<BlocksDownloadedEventListener>>()
    private val peersChainDownloadStartedEventListeners = CopyOnWriteArrayList<ListenerRegistration<ChainDownloadStartedEventListener>>()
    /** Callbacks for events related to peers connecting  */
    protected val peerConnectedEventListeners = CopyOnWriteArrayList<ListenerRegistration<PeerConnectedEventListener>>()
    /** Callbacks for events related to peer connection/disconnection  */
    protected val peerDiscoveredEventListeners = CopyOnWriteArrayList<ListenerRegistration<PeerDiscoveredEventListener>>()
    /** Callbacks for events related to peers disconnecting  */
    protected val peerDisconnectedEventListeners = CopyOnWriteArrayList<ListenerRegistration<PeerDisconnectedEventListener>>()
    /** Callbacks for events related to peer data being received  */
    private val peerGetDataEventListeners = CopyOnWriteArrayList<ListenerRegistration<GetDataEventListener>>()
    private val peersPreMessageReceivedEventListeners = CopyOnWriteArrayList<ListenerRegistration<PreMessageReceivedEventListener>>()
    protected val peersTransactionBroadastEventListeners = CopyOnWriteArrayList<ListenerRegistration<OnTransactionBroadcastListener>>()
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private val peerDiscoverers: CopyOnWriteArraySet<PeerDiscovery>
    // The version message to use for new connections.
    @GuardedBy("lock") private var versionMessage: VersionMessage? = null
    // Maximum depth up to which pending transaction dependencies are downloaded, or 0 for disabled.
    @GuardedBy("lock") private var downloadTxDependencyDepth: Int = 0
    // How many connections we want to have open at the current time. If we lose connections, we'll try opening more
    // until we reach this count.
    @GuardedBy("lock") private var maxConnections: Int = 0
    // Minimum protocol version we will allow ourselves to connect to: require Bloom filtering.
    /** The minimum protocol version required: defaults to the version required for Bloom filtering.  */
    /**
     * If a peer is connected to that claims to speak a protocol version lower than the given version, it will
     * be disconnected and another one will be tried instead.
     */
    @Volatile
    var minRequiredProtocolVersion: Int = 0
    @GuardedBy("lock") private var pingIntervalMsec = DEFAULT_PING_INTERVAL_MSEC

    @GuardedBy("lock") private var useLocalhostPeerWhenPossible = true
    @GuardedBy("lock") private var ipv6Unreachable = false

    @GuardedBy("lock") private var fastCatchupTimeSecs: Long = 0
    private val wallets: CopyOnWriteArrayList<Wallet>
    private val peerFilterProviders: CopyOnWriteArrayList<PeerFilterProvider>

    // This event listener is added to every peer. It's here so when we announce transactions via an "inv", every
    // peer can fetch them.
    private val peerListener = PeerListener()

    private var minBroadcastConnections = 0
    private val walletScriptEventListener = ScriptsChangeEventListener { wallet, scripts, isAddingScripts -> recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED) }

    private val walletKeyEventListener = KeyChainEventListener { recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED) }

    private val walletCoinsReceivedEventListener = WalletCoinsReceivedEventListener { wallet, tx, prevBalance, newBalance ->
        // We received a relevant transaction. We MAY need to recalculate and resend the Bloom filter, but only
        // if we have received a transaction that includes a relevant pay-to-pubkey output.
        //
        // The reason is that pay-to-pubkey outputs, when spent, will not repeat any data we can predict in their
        // inputs. So a remote peer will update the Bloom filter for us when such an output is seen matching the
        // existing filter, so that it includes the tx hash in which the pay-to-pubkey output was observed. Thus
        // the spending transaction will always match (due to the outpoint structure).
        //
        // Unfortunately, whilst this is required for correct sync of the chain in blocks, there are two edge cases.
        //
        // (1) If a wallet receives a relevant, confirmed p2pubkey output that was not broadcast across the network,
        // for example in a coinbase transaction, then the node that's serving us the chain will update its filter
        // but the rest will not. If another transaction then spends it, the other nodes won't match/relay it.
        //
        // (2) If we receive a p2pubkey output broadcast across the network, all currently connected nodes will see
        // it and update their filter themselves, but any newly connected nodes will receive the last filter we
        // calculated, which would not include this transaction.
        //
        // For this reason we check if the transaction contained any relevant pay to pubkeys and force a recalc
        // and possibly retransmit if so. The recalculation process will end up including the tx hash into the
        // filter. In case (1), we need to retransmit the filter to the connected peers. In case (2), we don't
        // and shouldn't, we should just recalculate and cache the new filter for next time.
        for (output in tx.outputs) {
            if (output.scriptPubKey.isSentToRawPubKey && output.isMine(wallet)) {
                if (tx.confidence.confidenceType == TransactionConfidence.ConfidenceType.BUILDING)
                    recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED)
                else
                    recalculateFastCatchupAndFilter(FilterRecalculateMode.DONT_SEND)
                return@WalletCoinsReceivedEventListener
            }
        }
    }

    // Exponential backoff for peers starts at 1 second and maxes at 10 minutes.
    private val peerBackoffParams = ExponentialBackoff.Params(1000, 1.5f, (10 * 60 * 1000).toLong())
    // Tracks failures globally in case of a network failure.
    @GuardedBy("lock") private val groupBackoff = ExponentialBackoff(ExponentialBackoff.Params(1000, 1.5f, (10 * 1000).toLong()))

    // This is a synchronized set, so it locks on itself. We use it to prevent TransactionBroadcast objects from
    // being garbage collected if nothing in the apps code holds on to them transitively. See the discussion
    // in broadcastTransaction.
    private val runningBroadcasts: MutableSet<TransactionBroadcast>

    private val startupListener = PeerStartupListener()
    // An object that calculates bloom filters given a list of filter providers, whilst tracking some state useful
    // for privacy purposes.
    private val bloomFilterMerger: FilterMerger
    @Volatile private var vConnectTimeoutMillis = DEFAULT_CONNECT_TIMEOUT_MILLIS

    /** Whether bloom filter support is enabled when using a non FullPrunedBlockchain */
    /** Returns whether the Bloom filtering protocol optimisation is in use: defaults to true.  */
    /**
     * Can be used to disable Bloom filtering entirely, even in SPV mode. You are very unlikely to need this, it is
     * an optimisation for rare cases when full validation is not required but it's still more efficient to download
     * full blocks than filtered blocks.
     */
    @Volatile
    var isBloomFilteringEnabled = true

    private val executorStartupLatch = CountDownLatch(1)

    private val triggerConnectionsJob = object : Runnable {
        private var firstRun = true
        private val MIN_PEER_DISCOVERY_INTERVAL = 1000L

        override fun run() {
            try {
                go()
            } catch (e: Throwable) {
                log.error("Exception when trying to build connections", e)  // The executor swallows exceptions :(
            }

        }

        fun go() {
            if (!isRunning) return

            var doDiscovery = false
            val now = Utils.currentTimeMillis()
            lock.lock()
            try {
                // First run: try and use a local node if there is one, for the additional security it can provide.
                // But, not on Android as there are none for this platform: it could only be a malicious app trying
                // to hijack our traffic.
                if (!Utils.isAndroidRuntime && useLocalhostPeerWhenPossible && maybeCheckForLocalhostPeer() && firstRun) {
                    log.info("Localhost peer detected, trying to use it instead of P2P discovery")
                    maxConnections = 0
                    connectToLocalHost()
                    return
                }

                val havePeerWeCanTry = !inactives.isEmpty() && backoffMap[inactives.peek()].getRetryTime() <= now
                doDiscovery = !havePeerWeCanTry
            } finally {
                firstRun = false
                lock.unlock()
            }

            // Don't hold the lock across discovery as this process can be very slow.
            var discoverySuccess = false
            if (doDiscovery) {
                try {
                    discoverySuccess = discoverPeers() > 0
                } catch (e: PeerDiscoveryException) {
                    log.error("Peer discovery failure", e)
                }

            }

            var retryTime: Long
            var addrToTry: PeerAddress?
            lock.lock()
            try {
                if (doDiscovery) {
                    // Require that we have enough connections, to consider this
                    // a success, or we just constantly test for new peers
                    if (discoverySuccess && countConnectedAndPendingPeers() >= getMaxConnections()) {
                        groupBackoff.trackSuccess()
                    } else {
                        groupBackoff.trackFailure()
                    }
                }
                // Inactives is sorted by backoffMap time.
                if (inactives.isEmpty()) {
                    if (countConnectedAndPendingPeers() < getMaxConnections()) {
                        val interval = Math.max(groupBackoff.retryTime - now, MIN_PEER_DISCOVERY_INTERVAL)
                        log.info("Peer discovery didn't provide us any more peers, will try again in "
                                + interval + "ms.")
                        executor.schedule(this, interval, TimeUnit.MILLISECONDS)
                    } else {
                        // We have enough peers and discovery provided no more, so just settle down. Most likely we
                        // were given a fixed set of addresses in some test scenario.
                    }
                    return
                } else {
                    do {
                        addrToTry = inactives.poll()
                    } while (ipv6Unreachable && addrToTry!!.addr is Inet6Address)
                    retryTime = backoffMap[addrToTry].getRetryTime()
                }
                retryTime = Math.max(retryTime, groupBackoff.retryTime)
                if (retryTime > now) {
                    val delay = retryTime - now
                    log.info("Waiting {} msec before next connect attempt {}", delay, if (addrToTry == null) "" else "to " + addrToTry)
                    inactives.add(addrToTry)
                    executor.schedule(this, delay, TimeUnit.MILLISECONDS)
                    return
                }
                connectTo(addrToTry, false, vConnectTimeoutMillis)
            } finally {
                lock.unlock()
            }
            if (countConnectedAndPendingPeers() < getMaxConnections()) {
                executor.execute(this)   // Try next peer immediately.
            }
        }
    }

    /**
     * Returns a newly allocated list containing the currently connected peers. If all you care about is the count,
     * use numConnectedPeers().
     */
    val connectedPeers: List<Peer>
        get() {
            lock.lock()
            try {
                return ArrayList(peers)
            } finally {
                lock.unlock()
            }
        }
    private var localhostCheckState = LocalhostCheckState.NOT_TRIED

    private val inFlightRecalculations = Maps.newHashMap<FilterRecalculateMode, SettableFuture<BloomFilter>>()

    @Volatile private var vPingTask: ListenableScheduledFuture<*>? = null

    /** Use "Context.get().getConfidenceTable()" instead  */
    val memoryPool: TxConfidenceTable?
        @Deprecated("")
        get() = Context.get()!!.confidenceTable

    @GuardedBy("lock") private var stallPeriodSeconds = 10
    @GuardedBy("lock") private var stallMinSpeedBytesSec = Block.HEADER_SIZE * 20
    private var chainDownloadSpeedCalculator: ChainDownloadSpeedCalculator? = null

    /**
     * Returns our peers most commonly reported chain height. If multiple heights are tied, the highest is returned.
     * If no peers are connected, returns zero.
     */
    val mostCommonChainHeight: Int
        get() {
            lock.lock()
            try {
                return getMostCommonChainHeight(this.peers)
            } finally {
                lock.unlock()
            }
        }

    private inner class PeerListener : GetDataEventListener, BlocksDownloadedEventListener {

        override fun getData(peer: Peer, m: GetDataMessage): List<Message>? {
            return handleGetData(m)
        }

        override fun onBlocksDownloaded(peer: Peer, block: Block, filteredBlock: FilteredBlock?, blocksLeft: Int) {
            if (chain == null) return
            val rate = chain.falsePositiveRate
            val target = bloomFilterMerger.bloomFilterFPRate * MAX_FP_RATE_INCREASE
            if (rate > target) {
                // TODO: Avoid hitting this path if the remote peer didn't acknowledge applying a new filter yet.
                if (log.isDebugEnabled())
                    log.debug("Force update Bloom filter due to high false positive rate ({} vs {})", rate, target)
                recalculateFastCatchupAndFilter(FilterRecalculateMode.FORCE_SEND_FOR_REFRESH)
            }
        }
    }

    private inner class PeerStartupListener : PeerConnectedEventListener, PeerDisconnectedEventListener {
        override fun onPeerConnected(peer: Peer, peerCount: Int) {
            handleNewPeer(peer)
        }

        override fun onPeerDisconnected(peer: Peer, peerCount: Int) {
            // The channel will be automatically removed from channels.
            handlePeerDeath(peer, null)
        }
    }

    /** See [.PeerGroup]  */
    @JvmOverloads constructor(params: NetworkParameters, chain: AbstractBlockChain? = null) : this(Context.getOrCreate(params), chain, NioClientManager()) {}

    /** See [.PeerGroup]  */
    constructor(params: NetworkParameters, chain: AbstractBlockChain?, connectionManager: ClientConnectionManager) : this(Context.getOrCreate(params), chain, connectionManager, null) {}

    /**
     * Creates a new PeerGroup allowing you to specify the [ClientConnectionManager] which is used to create new
     * connections and keep track of existing ones.
     */
    @JvmOverloads constructor(context: Context, chain: AbstractBlockChain? = null, connectionManager: ClientConnectionManager = NioClientManager()) : this(context, chain, connectionManager, null) {}

    init {
        checkNotNull(context)
        this.params = context.params
        fastCatchupTimeSecs = params.genesisBlock.timeSeconds
        wallets = CopyOnWriteArrayList()
        peerFilterProviders = CopyOnWriteArrayList()

        executor = createPrivateExecutor()

        // This default sentinel value will be overridden by one of two actions:
        //   - adding a peer discovery source sets it to the default
        //   - using connectTo() will increment it by one
        maxConnections = 0

        val height = chain?.bestChainHeight ?: 0
        versionMessage = VersionMessage(params, height)
        // We never request that the remote node wait for a bloom filter yet, as we have no wallets
        versionMessage!!.relayTxesBeforeFilter = true

        downloadTxDependencyDepth = Integer.MAX_VALUE

        inactives = PriorityQueue(1, Comparator { a, b ->
            // only called when inactives is accessed, and lock is held then.
            checkState(lock.isHeldByCurrentThread)
            var result = backoffMap[a].compareTo(backoffMap[b])
            // Sort by port if otherwise equals - for testing
            if (result == 0)
                result = Ints.compare(a.port, b.port)
            result
        })
        backoffMap = HashMap()
        peers = CopyOnWriteArrayList()
        pendingPeers = CopyOnWriteArrayList()
        peerDiscoverers = CopyOnWriteArraySet()
        runningBroadcasts = Collections.synchronizedSet(HashSet())
        bloomFilterMerger = FilterMerger(DEFAULT_BLOOM_FILTER_FP_RATE)
        minRequiredProtocolVersion = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.BLOOM_FILTER)
    }

    protected open fun createPrivateExecutor(): ListeningScheduledExecutorService {
        val result = MoreExecutors.listeningDecorator(
                ScheduledThreadPoolExecutor(1, ContextPropagatingThreadFactory("PeerGroup Thread"))
        )
        // Hack: jam the executor so jobs just queue up until the user calls start() on us. For example, adding a wallet
        // results in a bloom filter recalc being queued, but we don't want to do that until we're actually started.
        result.execute { Uninterruptibles.awaitUninterruptibly(executorStartupLatch) }
        return result
    }

    /**
     * This is how many milliseconds we wait for peer discoveries to return their results.
     */
    fun setPeerDiscoveryTimeoutMillis(peerDiscoveryTimeoutMillis: Long) {
        this.vPeerDiscoveryTimeoutMillis = peerDiscoveryTimeoutMillis
    }

    /**
     * Adjusts the desired number of connections that we will create to peers. Note that if there are already peers
     * open and the new value is lower than the current number of peers, those connections will be terminated. Likewise
     * if there aren't enough current connections to meet the new requested max size, some will be added.
     */
    fun setMaxConnections(maxConnections: Int) {
        val adjustment: Int
        lock.lock()
        try {
            this.maxConnections = maxConnections
            if (!isRunning) return
        } finally {
            lock.unlock()
        }
        // We may now have too many or too few open connections. Add more or drop some to get to the right amount.
        adjustment = maxConnections - channels.connectedClientCount
        if (adjustment > 0)
            triggerConnections()

        if (adjustment < 0)
            channels.closeConnections(-adjustment)
    }

    /**
     * Configure download of pending transaction dependencies. A change of values only takes effect for newly connected
     * peers.
     */
    fun setDownloadTxDependencies(depth: Int) {
        lock.lock()
        try {
            this.downloadTxDependencyDepth = depth
        } finally {
            lock.unlock()
        }
    }

    private fun triggerConnections() {
        // Run on a background thread due to the need to potentially retry and back off in the background.
        if (!executor.isShutdown)
            executor.execute(triggerConnectionsJob)
    }

    /** The maximum number of connections that we will create to peers.  */
    fun getMaxConnections(): Int {
        lock.lock()
        try {
            return maxConnections
        } finally {
            lock.unlock()
        }
    }

    private fun handleGetData(m: GetDataMessage): List<Message> {
        // Scans the wallets and memory pool for transactions in the getdata message and returns them.
        // Runs on peer threads.
        lock.lock()
        try {
            val transactions = LinkedList<Message>()
            val items = LinkedList(m.getItems())
            val it = items.iterator()
            while (it.hasNext()) {
                val item = it.next()
                // Check the wallets.
                for (w in wallets) {
                    val tx = w.getTransaction(item.hash) ?: continue
                    transactions.add(tx)
                    it.remove()
                    break
                }
            }
            return transactions
        } finally {
            lock.unlock()
        }
    }

    /**
     * Sets the [VersionMessage] that will be announced on newly created connections. A version message is
     * primarily interesting because it lets you customize the "subVer" field which is used a bit like the User-Agent
     * field from HTTP. It means your client tells the other side what it is, see
     * [BIP 14](https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki).
     *
     * The VersionMessage you provide is copied and the best chain height/time filled in for each new connection,
     * therefore you don't have to worry about setting that. The provided object is really more of a template.
     */
    fun setVersionMessage(ver: VersionMessage) {
        lock.lock()
        try {
            versionMessage = ver
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns the version message provided by setVersionMessage or a default if none was given.
     */
    fun getVersionMessage(): VersionMessage? {
        lock.lock()
        try {
            return versionMessage
        } finally {
            lock.unlock()
        }
    }

    /**
     * Sets information that identifies this software to remote nodes. This is a convenience wrapper for creating
     * a new [VersionMessage], calling [VersionMessage.appendToSubVer] on it,
     * and then calling [PeerGroup.setVersionMessage] on the result of that. See the docs for
     * [VersionMessage.appendToSubVer] for information on what the fields should contain.
     */
    @JvmOverloads
    fun setUserAgent(name: String, version: String, comments: String? = null) {
        //TODO Check that height is needed here (it wasnt, but it should be, no?)
        val height = chain?.bestChainHeight ?: 0
        val ver = VersionMessage(params, height)
        ver.relayTxesBeforeFilter = false
        updateVersionMessageRelayTxesBeforeFilter(ver)
        ver.appendToSubVer(name, version, comments)
        setVersionMessage(ver)
    }

    // Updates the relayTxesBeforeFilter flag of ver
    private fun updateVersionMessageRelayTxesBeforeFilter(ver: VersionMessage) {
        // We will provide the remote node with a bloom filter (ie they shouldn't relay yet)
        // if chain == null || !chain.shouldVerifyTransactions() and a wallet is added and bloom filters are enabled
        // Note that the default here means that no tx invs will be received if no wallet is ever added
        lock.lock()
        try {
            val spvMode = chain != null && !chain.shouldVerifyTransactions()
            val willSendFilter = spvMode && peerFilterProviders.size > 0 && isBloomFilteringEnabled
            ver.relayTxesBeforeFilter = !willSendFilter
        } finally {
            lock.unlock()
        }
    }

    /** Use the more specific listener methods instead  */
    @Deprecated("")
    fun addEventListener(listener: AbstractPeerEventListener, executor: Executor) {
        addBlocksDownloadedEventListener(Threading.USER_THREAD, listener)
        addChainDownloadStartedEventListener(Threading.USER_THREAD, listener)
        addConnectedEventListener(Threading.USER_THREAD, listener)
        addDisconnectedEventListener(Threading.USER_THREAD, listener)
        addDiscoveredEventListener(Threading.USER_THREAD, listener)
        addGetDataEventListener(Threading.USER_THREAD, listener)
        addOnTransactionBroadcastListener(Threading.USER_THREAD, listener)
        addPreMessageReceivedEventListener(Threading.USER_THREAD, listener)
    }

    /** Use the more specific listener methods instead  */
    @Deprecated("")
    fun addEventListener(listener: AbstractPeerEventListener) {
        addBlocksDownloadedEventListener(executor, listener)
        addChainDownloadStartedEventListener(executor, listener)
        addConnectedEventListener(executor, listener)
        addDisconnectedEventListener(executor, listener)
        addDiscoveredEventListener(executor, listener)
        addGetDataEventListener(executor, listener)
        addOnTransactionBroadcastListener(executor, listener)
        addPreMessageReceivedEventListener(executor, listener)
    }

    /** See [Peer.addBlocksDownloadedEventListener]  */
    fun addBlocksDownloadedEventListener(listener: BlocksDownloadedEventListener) {
        addBlocksDownloadedEventListener(Threading.USER_THREAD, listener)
    }

    /**
     *
     * Adds a listener that will be notified on the given executor when
     * blocks are downloaded by the download peer.
     * @see Peer.addBlocksDownloadedEventListener
     */
    fun addBlocksDownloadedEventListener(executor: Executor, listener: BlocksDownloadedEventListener) {
        peersBlocksDownloadedEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
        for (peer in connectedPeers)
            peer.addBlocksDownloadedEventListener(executor, listener)
        for (peer in getPendingPeers())
            peer.addBlocksDownloadedEventListener(executor, listener)
    }

    /** See [Peer.addBlocksDownloadedEventListener]  */
    fun addChainDownloadStartedEventListener(listener: ChainDownloadStartedEventListener) {
        addChainDownloadStartedEventListener(Threading.USER_THREAD, listener)
    }

    /**
     *
     * Adds a listener that will be notified on the given executor when
     * chain download starts.
     */
    fun addChainDownloadStartedEventListener(executor: Executor, listener: ChainDownloadStartedEventListener) {
        peersChainDownloadStartedEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
        for (peer in connectedPeers)
            peer.addChainDownloadStartedEventListener(executor, listener)
        for (peer in getPendingPeers())
            peer.addChainDownloadStartedEventListener(executor, listener)
    }

    /** See [Peer.addConnectedEventListener]  */
    fun addConnectedEventListener(listener: PeerConnectedEventListener) {
        addConnectedEventListener(Threading.USER_THREAD, listener)
    }

    /**
     *
     * Adds a listener that will be notified on the given executor when
     * new peers are connected to.
     */
    fun addConnectedEventListener(executor: Executor, listener: PeerConnectedEventListener) {
        peerConnectedEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
        for (peer in connectedPeers)
            peer.addConnectedEventListener(executor, listener)
        for (peer in getPendingPeers())
            peer.addConnectedEventListener(executor, listener)
    }

    /** See [Peer.addDisconnectedEventListener]  */
    fun addDisconnectedEventListener(listener: PeerDisconnectedEventListener) {
        addDisconnectedEventListener(Threading.USER_THREAD, listener)
    }

    /**
     *
     * Adds a listener that will be notified on the given executor when
     * peers are disconnected from.
     */
    fun addDisconnectedEventListener(executor: Executor, listener: PeerDisconnectedEventListener) {
        peerDisconnectedEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
        for (peer in connectedPeers)
            peer.addDisconnectedEventListener(executor, listener)
        for (peer in getPendingPeers())
            peer.addDisconnectedEventListener(executor, listener)
    }

    /** See [Peer.addDiscoveredEventListener]  */
    fun addDiscoveredEventListener(listener: PeerDiscoveredEventListener) {
        addDiscoveredEventListener(Threading.USER_THREAD, listener)
    }

    /**
     *
     * Adds a listener that will be notified on the given executor when new
     * peers are discovered.
     */
    fun addDiscoveredEventListener(executor: Executor, listener: PeerDiscoveredEventListener) {
        peerDiscoveredEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
    }

    /** See [Peer.addGetDataEventListener]  */
    fun addGetDataEventListener(listener: GetDataEventListener) {
        addGetDataEventListener(Threading.USER_THREAD, listener)
    }

    /** See [Peer.addGetDataEventListener]  */
    fun addGetDataEventListener(executor: Executor, listener: GetDataEventListener) {
        peerGetDataEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
        for (peer in connectedPeers)
            peer.addGetDataEventListener(executor, listener)
        for (peer in getPendingPeers())
            peer.addGetDataEventListener(executor, listener)
    }

    /** See [Peer.addOnTransactionBroadcastListener]  */
    fun addOnTransactionBroadcastListener(listener: OnTransactionBroadcastListener) {
        addOnTransactionBroadcastListener(Threading.USER_THREAD, listener)
    }

    /** See [Peer.addOnTransactionBroadcastListener]  */
    fun addOnTransactionBroadcastListener(executor: Executor, listener: OnTransactionBroadcastListener) {
        peersTransactionBroadastEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
        for (peer in connectedPeers)
            peer.addOnTransactionBroadcastListener(executor, listener)
        for (peer in getPendingPeers())
            peer.addOnTransactionBroadcastListener(executor, listener)
    }

    /** See [Peer.addPreMessageReceivedEventListener]  */
    fun addPreMessageReceivedEventListener(listener: PreMessageReceivedEventListener) {
        addPreMessageReceivedEventListener(Threading.USER_THREAD, listener)
    }

    /** See [Peer.addPreMessageReceivedEventListener]  */
    fun addPreMessageReceivedEventListener(executor: Executor, listener: PreMessageReceivedEventListener) {
        peersPreMessageReceivedEventListeners.add(ListenerRegistration(checkNotNull(listener), executor))
        for (peer in connectedPeers)
            peer.addPreMessageReceivedEventListener(executor, listener)
        for (peer in getPendingPeers())
            peer.addPreMessageReceivedEventListener(executor, listener)
    }

    /** Use the more specific listener methods instead  */
    @Deprecated("")
    fun removeEventListener(listener: AbstractPeerEventListener) {
        removeBlocksDownloadedEventListener(listener)
        removeChainDownloadStartedEventListener(listener)
        removeConnectedEventListener(listener)
        removeDisconnectedEventListener(listener)
        removeDiscoveredEventListener(listener)
        removeGetDataEventListener(listener)
        removeOnTransactionBroadcastListener(listener)
        removePreMessageReceivedEventListener(listener)
    }

    fun removeBlocksDownloadedEventListener(listener: BlocksDownloadedEventListener): Boolean {
        val result = ListenerRegistration.removeFromList(listener, peersBlocksDownloadedEventListeners)
        for (peer in connectedPeers)
            peer.removeBlocksDownloadedEventListener(listener)
        for (peer in getPendingPeers())
            peer.removeBlocksDownloadedEventListener(listener)
        return result
    }

    fun removeChainDownloadStartedEventListener(listener: ChainDownloadStartedEventListener): Boolean {
        val result = ListenerRegistration.removeFromList(listener, peersChainDownloadStartedEventListeners)
        for (peer in connectedPeers)
            peer.removeChainDownloadStartedEventListener(listener)
        for (peer in getPendingPeers())
            peer.removeChainDownloadStartedEventListener(listener)
        return result
    }

    /** The given event listener will no longer be called with events.  */
    fun removeConnectedEventListener(listener: PeerConnectedEventListener): Boolean {
        val result = ListenerRegistration.removeFromList(listener, peerConnectedEventListeners)
        for (peer in connectedPeers)
            peer.removeConnectedEventListener(listener)
        for (peer in getPendingPeers())
            peer.removeConnectedEventListener(listener)
        return result
    }

    /** The given event listener will no longer be called with events.  */
    fun removeDisconnectedEventListener(listener: PeerDisconnectedEventListener): Boolean {
        val result = ListenerRegistration.removeFromList(listener, peerDisconnectedEventListeners)
        for (peer in connectedPeers)
            peer.removeDisconnectedEventListener(listener)
        for (peer in getPendingPeers())
            peer.removeDisconnectedEventListener(listener)
        return result
    }

    /** The given event listener will no longer be called with events.  */
    fun removeDiscoveredEventListener(listener: PeerDiscoveredEventListener): Boolean {
        return ListenerRegistration.removeFromList(listener, peerDiscoveredEventListeners)
    }

    /** The given event listener will no longer be called with events.  */
    fun removeGetDataEventListener(listener: GetDataEventListener): Boolean {
        val result = ListenerRegistration.removeFromList(listener, peerGetDataEventListeners)
        for (peer in connectedPeers)
            peer.removeGetDataEventListener(listener)
        for (peer in getPendingPeers())
            peer.removeGetDataEventListener(listener)
        return result
    }

    /** The given event listener will no longer be called with events.  */
    fun removeOnTransactionBroadcastListener(listener: OnTransactionBroadcastListener): Boolean {
        val result = ListenerRegistration.removeFromList(listener, peersTransactionBroadastEventListeners)
        for (peer in connectedPeers)
            peer.removeOnTransactionBroadcastListener(listener)
        for (peer in getPendingPeers())
            peer.removeOnTransactionBroadcastListener(listener)
        return result
    }

    fun removePreMessageReceivedEventListener(listener: PreMessageReceivedEventListener): Boolean {
        val result = ListenerRegistration.removeFromList(listener, peersPreMessageReceivedEventListeners)
        for (peer in connectedPeers)
            peer.removePreMessageReceivedEventListener(listener)
        for (peer in getPendingPeers())
            peer.removePreMessageReceivedEventListener(listener)
        return result
    }

    /**
     * Returns a list containing Peers that did not complete connection yet.
     */
    fun getPendingPeers(): List<Peer> {
        lock.lock()
        try {
            return ArrayList(pendingPeers)
        } finally {
            lock.unlock()
        }
    }

    /**
     * Add an address to the list of potential peers to connect to. It won't necessarily be used unless there's a need
     * to build new connections to reach the max connection count.
     *
     * @param peerAddress IP/port to use.
     */
    fun addAddress(peerAddress: PeerAddress) {
        val newMax: Int
        lock.lock()
        try {
            addInactive(peerAddress)
            newMax = getMaxConnections() + 1
        } finally {
            lock.unlock()
        }
        setMaxConnections(newMax)
    }

    private fun addInactive(peerAddress: PeerAddress) {
        lock.lock()
        try {
            // Deduplicate
            if (backoffMap.containsKey(peerAddress))
                return
            backoffMap.put(peerAddress, ExponentialBackoff(peerBackoffParams))
            inactives.offer(peerAddress)
        } finally {
            lock.unlock()
        }
    }

    /**
     * Convenience for connecting only to peers that can serve specific services. It will configure suitable peer
     * discoveries.
     * @param requiredServices Required services as a bitmask, e.g. [VersionMessage.NODE_NETWORK].
     */
    fun setRequiredServices(requiredServices: Long) {
        lock.lock()
        try {
            this.requiredServices = requiredServices
            peerDiscoverers.clear()
            addPeerDiscovery(MultiplexingDiscovery.forServices(params, requiredServices))
        } finally {
            lock.unlock()
        }
    }

    /** Convenience method for addAddress(new PeerAddress(address, params.port));  */
    fun addAddress(address: InetAddress) {
        addAddress(PeerAddress(params, address, params.port))
    }

    /**
     * Add addresses from a discovery source to the list of potential peers to connect to. If max connections has not
     * been configured, or set to zero, then it's set to the default at this point.
     */
    fun addPeerDiscovery(peerDiscovery: PeerDiscovery) {
        lock.lock()
        try {
            if (getMaxConnections() == 0)
                setMaxConnections(DEFAULT_CONNECTIONS)
            peerDiscoverers.add(peerDiscovery)
        } finally {
            lock.unlock()
        }
    }

    /** Returns number of discovered peers.  */
    @Throws(PeerDiscoveryException::class)
    protected fun discoverPeers(): Int {
        // Don't hold the lock whilst doing peer discovery: it can take a long time and cause high API latency.
        checkState(!lock.isHeldByCurrentThread)
        val maxPeersToDiscoverCount = this.maxPeersToDiscoverCount
        val peerDiscoveryTimeoutMillis = this.vPeerDiscoveryTimeoutMillis
        val watch = Stopwatch.createStarted()
        val addressList = Lists.newLinkedList<PeerAddress>()
        for (peerDiscovery in peerDiscoverers /* COW */) {
            val addresses: Array<InetSocketAddress>
            addresses = peerDiscovery.getPeers(requiredServices, peerDiscoveryTimeoutMillis, TimeUnit.MILLISECONDS)
            for (address in addresses) addressList.add(PeerAddress(params, address))
            if (addressList.size >= maxPeersToDiscoverCount) break
        }
        if (!addressList.isEmpty()) {
            for (address in addressList) {
                addInactive(address)
            }
            val peersDiscoveredSet = ImmutableSet.copyOf(addressList)
            for (registration in peerDiscoveredEventListeners /* COW */) {
                registration.executor.execute { registration.listener.onPeersDiscovered(peersDiscoveredSet) }
            }
        }
        watch.stop()
        log.info("Peer discovery took {} and returned {} items", watch, addressList.size)
        return addressList.size
    }

    @VisibleForTesting
    internal fun waitForJobQueue() {
        Futures.getUnchecked<*>(executor.submit(Runnables.doNothing()))
    }

    private fun countConnectedAndPendingPeers(): Int {
        lock.lock()
        try {
            return peers.size + pendingPeers.size
        } finally {
            lock.unlock()
        }
    }

    private enum class LocalhostCheckState {
        NOT_TRIED,
        FOUND,
        FOUND_AND_CONNECTED,
        NOT_THERE
    }

    private fun maybeCheckForLocalhostPeer(): Boolean {
        checkState(lock.isHeldByCurrentThread)
        if (localhostCheckState == LocalhostCheckState.NOT_TRIED) {
            // Do a fast blocking connect to see if anything is listening.
            var socket: Socket? = null
            try {
                socket = Socket()
                socket.connect(InetSocketAddress(InetAddresses.forString("127.0.0.1"), params.port), vConnectTimeoutMillis)
                localhostCheckState = LocalhostCheckState.FOUND
                return true
            } catch (e: IOException) {
                log.info("Localhost peer not detected.")
                localhostCheckState = LocalhostCheckState.NOT_THERE
            } finally {
                if (socket != null) {
                    try {
                        socket.close()
                    } catch (e: IOException) {
                        // Ignore.
                    }

                }
            }
        }
        return false
    }

    /**
     * Starts the PeerGroup and begins network activity.
     * @return A future that completes when first connection activity has been triggered (note: not first connection made).
     */
    fun startAsync(): ListenableFuture<*> {
        // This is run in a background thread by the Service implementation.
        if (chain == null) {
            // Just try to help catch what might be a programming error.
            log.warn("Starting up with no attached block chain. Did you forget to pass one to the constructor?")
        }
        checkState(!vUsedUp, "Cannot start a peer group twice")
        isRunning = true
        vUsedUp = true
        executorStartupLatch.countDown()
        // We do blocking waits during startup, so run on the executor thread.
        return executor.submit {
            try {
                log.info("Starting ...")
                if (torClient != null) {
                    log.info("Starting Tor/Orchid ...")
                    torClient.start()
                    try {
                        torClient.waitUntilReady((TOR_TIMEOUT_SECONDS * 1000).toLong())
                    } catch (e: Exception) {
                        throw RuntimeException(e)
                    }

                    log.info("Tor ready")
                }
                channels.startAsync()
                channels.awaitRunning()
                triggerConnections()
                setupPinging()
            } catch (e: Throwable) {
                log.error("Exception when starting up", e)  // The executor swallows exceptions :(
            }
        }
    }

    /** Does a blocking startup.  */
    fun start() {
        Futures.getUnchecked(startAsync())
    }

    /** Can just use start() for a blocking start here instead of startAsync/awaitRunning: PeerGroup is no longer a Guava service.  */
    @Deprecated("")
    fun awaitRunning() {
        waitForJobQueue()
    }

    fun stopAsync(): ListenableFuture<*> {
        checkState(isRunning)
        isRunning = false
        val future = executor.submit {
            try {
                log.info("Stopping ...")
                // Blocking close of all sockets.
                channels.stopAsync()
                channels.awaitTerminated()
                for (peerDiscovery in peerDiscoverers) {
                    peerDiscovery.shutdown()
                }
                torClient?.stop()
                isRunning = false
                log.info("Stopped.")
            } catch (e: Throwable) {
                log.error("Exception when shutting down", e)  // The executor swallows exceptions :(
            }
        }
        executor.shutdown()
        return future
    }

    /** Does a blocking stop  */
    fun stop() {
        try {
            stopAsync()
            log.info("Awaiting PeerGroup shutdown ...")
            executor.awaitTermination(java.lang.Long.MAX_VALUE, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            throw RuntimeException(e)
        }

    }

    /** Can just use stop() here instead of stopAsync/awaitTerminated: PeerGroup is no longer a Guava service.  */
    @Deprecated("")
    fun awaitTerminated() {
        try {
            executor.awaitTermination(java.lang.Long.MAX_VALUE, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            throw RuntimeException(e)
        }

    }

    /**
     *
     * Link the given wallet to this PeerGroup. This is used for three purposes:
     *
     *
     *  1. So the wallet receives broadcast transactions.
     *  1. Announcing pending transactions that didn't get into the chain yet to our peers.
     *  1. Set the fast catchup time using [PeerGroup.setFastCatchupTimeSecs], to optimize chain
     * download.
     *
     *
     *
     * Note that this should be done before chain download commences because if you add a wallet with keys earlier
     * than the current chain head, the relevant parts of the chain won't be redownloaded for you.
     *
     *
     * The Wallet will have an event listener registered on it, so to avoid leaks remember to use
     * [PeerGroup.removeWallet] on it if you wish to keep the Wallet but lose the PeerGroup.
     */
    fun addWallet(wallet: Wallet) {
        lock.lock()
        try {
            checkNotNull(wallet)
            checkState(!wallets.contains(wallet))
            wallets.add(wallet)
            wallet.setTransactionBroadcaster(this)
            wallet.addCoinsReceivedEventListener(Threading.SAME_THREAD, walletCoinsReceivedEventListener)
            wallet.addKeyChainEventListener(Threading.SAME_THREAD, walletKeyEventListener)
            wallet.addScriptChangeEventListener(Threading.SAME_THREAD, walletScriptEventListener)
            addPeerFilterProvider(wallet)
            for (peer in peers) {
                peer.addWallet(wallet)
            }
        } finally {
            lock.unlock()
        }
    }

    /**
     *
     * Link the given PeerFilterProvider to this PeerGroup. DO NOT use this for Wallets, use
     * [PeerGroup.addWallet] instead.
     *
     *
     * Note that this should be done before chain download commences because if you add a listener with keys earlier
     * than the current chain head, the relevant parts of the chain won't be redownloaded for you.
     *
     *
     * This method invokes [PeerGroup.recalculateFastCatchupAndFilter].
     * The return value of this method is the `ListenableFuture` returned by that invocation.
     *
     * @return a future that completes once each `Peer` in this group has had its
     * `BloomFilter` (re)set.
     */
    fun addPeerFilterProvider(provider: PeerFilterProvider): ListenableFuture<BloomFilter> {
        lock.lock()
        try {
            checkNotNull(provider)
            checkState(!peerFilterProviders.contains(provider))
            // Insert provider at the start. This avoids various concurrency problems that could occur because we need
            // all providers to be in a consistent, unchanging state whilst the filter is built. Providers can give
            // this guarantee by taking a lock in their begin method, but if we add to the end of the list here, it
            // means we establish a lock ordering a > b > c if that's the order the providers were added in. Given that
            // the main wallet will usually be first, this establishes an ordering wallet > other-provider, which means
            // other-provider can then not call into the wallet itself. Other providers installed by the API user should
            // come first so the expected ordering is preserved. This can also manifest itself in providers that use
            // synchronous RPCs into an actor instead of locking, but the same issue applies.
            peerFilterProviders.add(0, provider)

            // Don't bother downloading block bodies before the oldest keys in all our wallets. Make sure we recalculate
            // if a key is added. Of course, by then we may have downloaded the chain already. Ideally adding keys would
            // automatically rewind the block chain and redownload the blocks to find transactions relevant to those keys,
            // all transparently and in the background. But we are a long way from that yet.
            val future = recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED)
            updateVersionMessageRelayTxesBeforeFilter(getVersionMessage()!!)
            return future
        } finally {
            lock.unlock()
        }
    }

    /**
     * Opposite of [.addPeerFilterProvider]. Again, don't use this for wallets. Does not
     * trigger recalculation of the filter.
     */
    fun removePeerFilterProvider(provider: PeerFilterProvider) {
        lock.lock()
        try {
            checkNotNull(provider)
            checkArgument(peerFilterProviders.remove(provider))
        } finally {
            lock.unlock()
        }
    }

    /**
     * Unlinks the given wallet so it no longer receives broadcast transactions or has its transactions announced.
     */
    fun removeWallet(wallet: Wallet) {
        wallets.remove(checkNotNull(wallet))
        peerFilterProviders.remove(wallet)
        wallet.removeCoinsReceivedEventListener(walletCoinsReceivedEventListener)
        wallet.removeKeyChainEventListener(walletKeyEventListener)
        wallet.removeScriptChangeEventListener(walletScriptEventListener)
        wallet.setTransactionBroadcaster(null)
        for (peer in peers) {
            peer.removeWallet(wallet)
        }
    }

    enum class FilterRecalculateMode {
        SEND_IF_CHANGED,
        FORCE_SEND_FOR_REFRESH,
        DONT_SEND
    }

    /**
     * Recalculates the bloom filter given to peers as well as the timestamp after which full blocks are downloaded
     * (instead of only headers). Note that calls made one after another may return the same future, if the request
     * wasn't processed yet (i.e. calls are deduplicated).
     *
     * @param mode In what situations to send the filter to connected peers.
     * @return a future that completes once the filter has been calculated (note: this does not mean acknowledged by remote peers).
     */
    fun recalculateFastCatchupAndFilter(mode: FilterRecalculateMode): ListenableFuture<BloomFilter> {
        val future = SettableFuture.create<BloomFilter>()
        synchronized(inFlightRecalculations) {
            if (inFlightRecalculations[mode] != null)
                return inFlightRecalculations[mode]
            inFlightRecalculations.put(mode, future)
        }
        val command = object : Runnable {
            override fun run() {
                try {
                    go()
                } catch (e: Throwable) {
                    log.error("Exception when trying to recalculate Bloom filter", e)  // The executor swallows exceptions :(
                }

            }

            fun go() {
                checkState(!lock.isHeldByCurrentThread)
                // Fully verifying mode doesn't use this optimization (it can't as it needs to see all transactions).
                if (chain != null && chain.shouldVerifyTransactions() || !isBloomFilteringEnabled)
                    return
                // We only ever call bloomFilterMerger.calculate on jobQueue, so we cannot be calculating two filters at once.
                val result = bloomFilterMerger.calculate(ImmutableList.copyOf(peerFilterProviders /* COW */))
                val send: Boolean
                when (mode) {
                    PeerGroup.FilterRecalculateMode.SEND_IF_CHANGED -> send = result.changed
                    PeerGroup.FilterRecalculateMode.DONT_SEND -> send = false
                    PeerGroup.FilterRecalculateMode.FORCE_SEND_FOR_REFRESH -> send = true
                    else -> throw UnsupportedOperationException()
                }
                if (send) {
                    for (peer in peers /* COW */) {
                        // Only query the mempool if this recalculation request is not in order to lower the observed FP
                        // rate. There's no point querying the mempool when doing this because the FP rate can only go
                        // down, and we will have seen all the relevant txns before: it's pointless to ask for them again.
                        peer.setBloomFilter(result.filter, mode != FilterRecalculateMode.FORCE_SEND_FOR_REFRESH)
                    }
                    // Reset the false positive estimate so that we don't send a flood of filter updates
                    // if the estimate temporarily overshoots our threshold.
                    chain?.resetFalsePositiveEstimate()
                }
                // Do this last so that bloomFilter is already set when it gets called.
                setFastCatchupTimeSecs(result.earliestKeyTimeSecs)
                synchronized(inFlightRecalculations) {
                    inFlightRecalculations.put(mode, null)
                }
                future.set(result.filter)
            }
        }
        try {
            executor.execute(command)
        } catch (e: RejectedExecutionException) {
            // Can happen during shutdown.
        }

        return future
    }

    /**
     *
     * Sets the false positive rate of bloom filters given to peers. The default is [.DEFAULT_BLOOM_FILTER_FP_RATE].
     *
     *
     * Be careful regenerating the bloom filter too often, as it decreases anonymity because remote nodes can
     * compare transactions against both the new and old filters to significantly decrease the false positive rate.
     *
     *
     * See the docs for [BloomFilter.BloomFilter] for a brief
     * explanation of anonymity when using bloom filters.
     */
    fun setBloomFilterFalsePositiveRate(bloomFilterFPRate: Double) {
        lock.lock()
        try {
            bloomFilterMerger.bloomFilterFPRate = bloomFilterFPRate
            recalculateFastCatchupAndFilter(FilterRecalculateMode.SEND_IF_CHANGED)
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns the number of currently connected peers. To be informed when this count changes, register a
     * [org.bitcoinj.core.listeners.PeerConnectionEventListener] and use the onPeerConnected/onPeerDisconnected methods.
     */
    fun numConnectedPeers(): Int {
        return peers.size
    }

    /**
     * Connect to a peer by creating a channel to the destination address.  This should not be
     * used normally - let the PeerGroup manage connections through [.start]
     *
     * @param address destination IP and port.
     * @return The newly created Peer object or null if the peer could not be connected.
     * Use [org.bitcoinj.core.Peer.getConnectionOpenFuture] if you
     * want a future which completes when the connection is open.
     */
    fun connectTo(address: InetSocketAddress): Peer? {
        lock.lock()
        try {
            val peerAddress = PeerAddress(params, address)
            backoffMap.put(peerAddress, ExponentialBackoff(peerBackoffParams))
            return connectTo(peerAddress, true, vConnectTimeoutMillis)
        } finally {
            lock.unlock()
        }
    }

    /**
     * Helper for forcing a connection to localhost. Useful when using regtest mode. Returns the peer object.
     */
    fun connectToLocalHost(): Peer? {
        lock.lock()
        try {
            val localhost = PeerAddress.localhost(params)
            backoffMap.put(localhost, ExponentialBackoff(peerBackoffParams))
            return connectTo(localhost, true, vConnectTimeoutMillis)
        } finally {
            lock.unlock()
        }
    }

    /**
     * Creates a version message to send, constructs a Peer object and attempts to connect it. Returns the peer on
     * success or null on failure.
     * @param address Remote network address
     * @param incrementMaxConnections Whether to consider this connection an attempt to fill our quota, or something
     * explicitly requested.
     * @return Peer or null.
     */
    @GuardedBy("lock")
    protected fun connectTo(address: PeerAddress?, incrementMaxConnections: Boolean, connectTimeoutMillis: Int): Peer? {
        checkState(lock.isHeldByCurrentThread)
        val ver = getVersionMessage()!!.duplicate()
        ver.bestHeight = (chain?.bestChainHeight ?: 0).toLong()
        ver.time = Utils.currentTimeSeconds()

        val peer = createPeer(address, ver)
        peer.addConnectedEventListener(Threading.SAME_THREAD, startupListener)
        peer.addDisconnectedEventListener(Threading.SAME_THREAD, startupListener)
        peer.setMinProtocolVersion(minRequiredProtocolVersion)
        pendingPeers.add(peer)

        try {
            log.info("Attempting connection to {}     ({} connected, {} pending, {} max)", address,
                    peers.size, pendingPeers.size, maxConnections)
            val future = channels.openConnection(address!!.toSocketAddress(), peer)
            if (future.isDone)
                Uninterruptibles.getUninterruptibly(future)
        } catch (e: ExecutionException) {
            val cause = Throwables.getRootCause(e)
            log.warn("Failed to connect to " + address + ": " + cause.message)
            handlePeerDeath(peer, cause)
            return null
        }

        peer.setSocketTimeout(connectTimeoutMillis)
        // When the channel has connected and version negotiated successfully, handleNewPeer will end up being called on
        // a worker thread.
        if (incrementMaxConnections) {
            // We don't use setMaxConnections here as that would trigger a recursive attempt to establish a new
            // outbound connection.
            maxConnections++
        }
        return peer
    }

    /** You can override this to customise the creation of [Peer] objects.  */
    @GuardedBy("lock")
    protected fun createPeer(address: PeerAddress?, ver: VersionMessage): Peer {
        return Peer(params, ver, address, chain, downloadTxDependencyDepth)
    }

    /**
     * Sets the timeout between when a connection attempt to a peer begins and when the version message exchange
     * completes. This does not apply to currently pending peers.
     */
    fun setConnectTimeoutMillis(connectTimeoutMillis: Int) {
        this.vConnectTimeoutMillis = connectTimeoutMillis
    }

    /**
     *
     * Start downloading the blockchain from the first available peer.
     *
     *
     * If no peers are currently connected, the download will be started once a peer starts.  If the peer dies,
     * the download will resume with another peer.
     *
     * @param listener a listener for chain download events, may not be null
     */
    fun startBlockChainDownload(listener: PeerDataEventListener?) {
        lock.lock()
        try {
            if (downloadPeer != null) {
                if (this.downloadListener != null) {
                    removeDataEventListenerFromPeer(downloadPeer!!, this.downloadListener)
                }
                if (listener != null) {
                    addDataEventListenerToPeer(Threading.USER_THREAD, downloadPeer!!, listener)
                }
            }
            this.downloadListener = listener
            // TODO: be more nuanced about which peer to download from.  We can also try
            // downloading from multiple peers and handle the case when a new peer comes along
            // with a longer chain after we thought we were done.
            if (!peers.isEmpty()) {
                startBlockChainDownloadFromPeer(peers.iterator().next()) // Will add the new download listener
            }
        } finally {
            lock.unlock()
        }
    }

    /**
     * Download the blockchain from peers. Convenience that uses a [DownloadProgressTracker] for you.
     *
     *
     *
     * This method waits until the download is complete.  "Complete" is defined as downloading
     * from at least one peer all the blocks that are in that peer's inventory.
     */
    fun downloadBlockChain() {
        val listener = DownloadProgressTracker()
        startBlockChainDownload(listener)
        try {
            listener.await()
        } catch (e: InterruptedException) {
            throw RuntimeException(e)
        }

    }

    protected fun handleNewPeer(peer: Peer) {
        var newSize = -1
        lock.lock()
        try {
            groupBackoff.trackSuccess()
            backoffMap[peer.address].trackSuccess()

            // Sets up the newly connected peer so it can do everything it needs to.
            pendingPeers.remove(peer)
            peers.add(peer)
            newSize = peers.size
            log.info("{}: New peer      ({} connected, {} pending, {} max)", peer, newSize, pendingPeers.size, maxConnections)
            // Give the peer a filter that can be used to probabilistically drop transactions that
            // aren't relevant to our wallet. We may still receive some false positives, which is
            // OK because it helps improve wallet privacy. Old nodes will just ignore the message.
            if (bloomFilterMerger.lastFilter != null) peer.bloomFilter = bloomFilterMerger.lastFilter
            peer.isDownloadData = false
            // TODO: The peer should calculate the fast catchup time from the added wallets here.
            for (wallet in wallets)
                peer.addWallet(wallet)
            if (downloadPeer == null) {
                // Kick off chain download if we aren't already doing it.
                setDownloadPeer(selectDownloadPeer(peers))
                val shouldDownloadChain = downloadListener != null && chain != null
                if (shouldDownloadChain) {
                    startBlockChainDownloadFromPeer(downloadPeer)
                }
            }
            // Make sure the peer knows how to upload transactions that are requested from us.
            peer.addBlocksDownloadedEventListener(Threading.SAME_THREAD, peerListener)
            peer.addGetDataEventListener(Threading.SAME_THREAD, peerListener)

            // And set up event listeners for clients. This will allow them to find out about new transactions and blocks.
            for (registration in peersBlocksDownloadedEventListeners)
                peer.addBlocksDownloadedEventListener(registration.executor, registration.listener)
            for (registration in peersChainDownloadStartedEventListeners)
                peer.addChainDownloadStartedEventListener(registration.executor, registration.listener)
            for (registration in peerConnectedEventListeners)
                peer.addConnectedEventListener(registration.executor, registration.listener)
            // We intentionally do not add disconnect listeners to peers
            for (registration in peerGetDataEventListeners)
                peer.addGetDataEventListener(registration.executor, registration.listener)
            for (registration in peersTransactionBroadastEventListeners)
                peer.addOnTransactionBroadcastListener(registration.executor, registration.listener)
            for (registration in peersPreMessageReceivedEventListeners)
                peer.addPreMessageReceivedEventListener(registration.executor, registration.listener)
        } finally {
            lock.unlock()
        }

        val fNewSize = newSize
        for (registration in peerConnectedEventListeners) {
            registration.executor.execute { registration.listener.onPeerConnected(peer, fNewSize) }
        }
    }

    private fun setupPinging() {
        if (getPingIntervalMsec() <= 0)
            return   // Disabled.

        vPingTask = executor.scheduleAtFixedRate(Runnable {
            try {
                if (getPingIntervalMsec() <= 0) {
                    val task = vPingTask
                    if (task != null) {
                        task.cancel(false)
                        vPingTask = null
                    }
                    return@Runnable   // Disabled.
                }
                for (peer in connectedPeers) {
                    if (peer.peerVersionMessage!!.clientVersion < params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.PONG))
                        continue
                    peer.ping()
                }
            } catch (e: Throwable) {
                log.error("Exception in ping loop", e)  // The executor swallows exceptions :(
            }
        }, getPingIntervalMsec(), getPingIntervalMsec(), TimeUnit.MILLISECONDS)
    }

    private fun setDownloadPeer(peer: Peer?) {
        lock.lock()
        try {
            if (downloadPeer === peer)
                return
            if (downloadPeer != null) {
                log.info("Unsetting download peer: {}", downloadPeer)
                if (downloadListener != null) {
                    removeDataEventListenerFromPeer(downloadPeer!!, downloadListener)
                }
                downloadPeer!!.isDownloadData = false
            }
            downloadPeer = peer
            if (downloadPeer != null) {
                log.info("Setting download peer: {}", downloadPeer)
                if (downloadListener != null) {
                    addDataEventListenerToPeer(Threading.SAME_THREAD, peer!!, downloadListener)
                }
                downloadPeer!!.isDownloadData = true
                if (chain != null)
                    downloadPeer!!.setDownloadParameters(fastCatchupTimeSecs, bloomFilterMerger.lastFilter != null)
            }
        } finally {
            lock.unlock()
        }
    }

    /**
     * Tells the PeerGroup to download only block headers before a certain time and bodies after that. Call this
     * before starting block chain download.
     * Do not use a time > NOW - 1 block, as it will break some block download logic.
     */
    fun setFastCatchupTimeSecs(secondsSinceEpoch: Long) {
        lock.lock()
        try {
            checkState(chain == null || !chain.shouldVerifyTransactions(), "Fast catchup is incompatible with fully verifying")
            fastCatchupTimeSecs = secondsSinceEpoch
            if (downloadPeer != null) {
                downloadPeer!!.setDownloadParameters(secondsSinceEpoch, bloomFilterMerger.lastFilter != null)
            }
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns the current fast catchup time. The contents of blocks before this time won't be downloaded as they
     * cannot contain any interesting transactions. If you use [PeerGroup.addWallet] this just returns
     * the min of the wallets earliest key times.
     * @return a time in seconds since the epoch
     */
    fun getFastCatchupTimeSecs(): Long {
        lock.lock()
        try {
            return fastCatchupTimeSecs
        } finally {
            lock.unlock()
        }
    }

    protected fun handlePeerDeath(peer: Peer, exception: Throwable?) {
        // Peer deaths can occur during startup if a connect attempt after peer discovery aborts immediately.
        if (!isRunning) return

        val numPeers: Int
        var numConnectedPeers = 0
        lock.lock()
        try {
            pendingPeers.remove(peer)
            peers.remove(peer)

            val address = peer.address

            log.info("{}: Peer died      ({} connected, {} pending, {} max)", address, peers.size, pendingPeers.size, maxConnections)
            if (peer === downloadPeer) {
                log.info("Download peer died. Picking a new one.")
                setDownloadPeer(null)
                // Pick a new one and possibly tell it to download the chain.
                val newDownloadPeer = selectDownloadPeer(peers)
                if (newDownloadPeer != null) {
                    setDownloadPeer(newDownloadPeer)
                    if (downloadListener != null) {
                        startBlockChainDownloadFromPeer(newDownloadPeer)
                    }
                }
            }
            numPeers = peers.size + pendingPeers.size
            numConnectedPeers = peers.size

            groupBackoff.trackFailure()

            if (exception is NoRouteToHostException) {
                if (address!!.addr is Inet6Address && !ipv6Unreachable) {
                    ipv6Unreachable = true
                    log.warn("IPv6 peer connect failed due to routing failure, ignoring IPv6 addresses from now on")
                }
            } else {
                backoffMap[address].trackFailure()
                // Put back on inactive list
                inactives.offer(address!!)
            }

            if (numPeers < getMaxConnections()) {
                triggerConnections()
            }
        } finally {
            lock.unlock()
        }

        peer.removeBlocksDownloadedEventListener(peerListener)
        peer.removeGetDataEventListener(peerListener)
        for (wallet in wallets) {
            peer.removeWallet(wallet)
        }

        val fNumConnectedPeers = numConnectedPeers

        for (registration in peersBlocksDownloadedEventListeners)
            peer.removeBlocksDownloadedEventListener(registration.listener)
        for (registration in peersChainDownloadStartedEventListeners)
            peer.removeChainDownloadStartedEventListener(registration.listener)
        for (registration in peerGetDataEventListeners)
            peer.removeGetDataEventListener(registration.listener)
        for (registration in peersPreMessageReceivedEventListeners)
            peer.removePreMessageReceivedEventListener(registration.listener)
        for (registration in peersTransactionBroadastEventListeners)
            peer.removeOnTransactionBroadcastListener(registration.listener)
        for (registration in peerDisconnectedEventListeners) {
            registration.executor.execute { registration.listener.onPeerDisconnected(peer, fNumConnectedPeers) }
            peer.removeDisconnectedEventListener(registration.listener)
        }
    }

    /**
     * Configures the stall speed: the speed at which a peer is considered to be serving us the block chain
     * unacceptably slowly. Once a peer has served us data slower than the given data rate for the given
     * number of seconds, it is considered stalled and will be disconnected, forcing the chain download to continue
     * from a different peer. The defaults are chosen conservatively, but if you are running on a platform that is
     * CPU constrained or on a very slow network e.g. EDGE, the default settings may need adjustment to
     * avoid false stalls.
     *
     * @param periodSecs How many seconds the download speed must be below blocksPerSec, defaults to 10.
     * @param bytesPerSecond Download speed (only blocks/txns count) must be consistently below this for a stall, defaults to the bandwidth required for 20 block headers per second.
     */
    fun setStallThreshold(periodSecs: Int, bytesPerSecond: Int) {
        lock.lock()
        try {
            stallPeriodSeconds = periodSecs
            stallMinSpeedBytesSec = bytesPerSecond
        } finally {
            lock.unlock()
        }
    }

    private inner class ChainDownloadSpeedCalculator : BlocksDownloadedEventListener, Runnable {
        private var blocksInLastSecond: Int = 0
        private var txnsInLastSecond: Int = 0
        private var origTxnsInLastSecond: Int = 0
        private var bytesInLastSecond: Long = 0

        // If we take more stalls than this, we assume we're on some kind of terminally slow network and the
        // stall threshold just isn't set properly. We give up on stall disconnects after that.
        private var maxStalls = 3

        // How many seconds the peer has until we start measuring its speed.
        private var warmupSeconds = -1

        // Used to calculate a moving average.
        private var samples: LongArray? = null
        private var cursor: Int = 0

        private var syncDone: Boolean = false

        @Synchronized override fun onBlocksDownloaded(peer: Peer, block: Block, filteredBlock: FilteredBlock?, blocksLeft: Int) {
            blocksInLastSecond++
            bytesInLastSecond += Block.HEADER_SIZE.toLong()
            val blockTransactions = block.getTransactions()
            // This whole area of the type hierarchy is a mess.
            val txCount = (if (blockTransactions != null) countAndMeasureSize(blockTransactions) else 0) + if (filteredBlock != null) countAndMeasureSize(filteredBlock.associatedTransactions.values) else 0
            txnsInLastSecond = txnsInLastSecond + txCount
            if (filteredBlock != null)
                origTxnsInLastSecond += filteredBlock.transactionCount
        }

        private fun countAndMeasureSize(transactions: Collection<Transaction>): Int {
            for (transaction in transactions)
                bytesInLastSecond += transaction.messageSize.toLong()
            return transactions.size
        }

        override fun run() {
            try {
                calculate()
            } catch (e: Throwable) {
                log.error("Error in speed calculator", e)
            }

        }

        private fun calculate() {
            val minSpeedBytesPerSec: Int
            val period: Int

            lock.lock()
            try {
                minSpeedBytesPerSec = stallMinSpeedBytesSec
                period = stallPeriodSeconds
            } finally {
                lock.unlock()
            }

            synchronized(this) {
                if (samples == null || samples!!.size != period) {
                    samples = LongArray(period)
                    // *2 because otherwise a single low sample could cause an immediate disconnect which is too harsh.
                    Arrays.fill(samples!!, (minSpeedBytesPerSec * 2).toLong())
                    warmupSeconds = 15
                }

                val behindPeers = chain != null && chain.bestChainHeight < mostCommonChainHeight
                if (!behindPeers)
                    syncDone = true
                if (!syncDone) {
                    if (warmupSeconds < 0) {
                        // Calculate the moving average.
                        samples[cursor++] = bytesInLastSecond
                        if (cursor == samples!!.size) cursor = 0
                        var average: Long = 0
                        for (sample in samples!!) average += sample
                        average /= samples!!.size.toLong()

                        log.info(String.format(Locale.US, "%d blocks/sec, %d tx/sec, %d pre-filtered tx/sec, avg/last %.2f/%.2f kilobytes per sec (stall threshold <%.2f KB/sec for %d seconds)",
                                blocksInLastSecond, txnsInLastSecond, origTxnsInLastSecond, average / 1024.0, bytesInLastSecond / 1024.0,
                                minSpeedBytesPerSec / 1024.0, samples!!.size))

                        if (average < minSpeedBytesPerSec && maxStalls > 0) {
                            maxStalls--
                            if (maxStalls == 0) {
                                // We could consider starting to drop the Bloom filtering FP rate at this point, because
                                // we tried a bunch of peers and no matter what we don't seem to be able to go any faster.
                                // This implies we're bandwidth bottlenecked and might want to start using bandwidth
                                // more effectively. Of course if there's a MITM that is deliberately throttling us,
                                // this is a good way to make us take away all the FPs from our Bloom filters ... but
                                // as they don't give us a whole lot of privacy either way that's not inherently a big
                                // deal.
                                log.warn("This network seems to be slower than the requested stall threshold - won't do stall disconnects any more.")
                            } else {
                                val peer = getDownloadPeer()
                                log.warn(String.format(Locale.US, "Chain download stalled: received %.2f KB/sec for %d seconds, require average of %.2f KB/sec, disconnecting %s", average / 1024.0, samples!!.size, minSpeedBytesPerSec / 1024.0, peer))
                                peer!!.close()
                                // Reset the sample buffer and give the next peer time to get going.
                                samples = null
                                warmupSeconds = period
                            }
                        }
                    } else {
                        warmupSeconds--
                        if (bytesInLastSecond > 0)
                            log.info(String.format(Locale.US, "%d blocks/sec, %d tx/sec, %d pre-filtered tx/sec, last %.2f kilobytes per sec",
                                    blocksInLastSecond, txnsInLastSecond, origTxnsInLastSecond, bytesInLastSecond / 1024.0))
                    }
                }
                blocksInLastSecond = 0
                txnsInLastSecond = 0
                origTxnsInLastSecond = 0
                bytesInLastSecond = 0
            }
        }
    }

    private fun startBlockChainDownloadFromPeer(peer: Peer?) {
        lock.lock()
        try {
            setDownloadPeer(peer)

            if (chainDownloadSpeedCalculator == null) {
                // Every second, run the calculator which will log how fast we are downloading the chain.
                chainDownloadSpeedCalculator = ChainDownloadSpeedCalculator()
                executor.scheduleAtFixedRate(chainDownloadSpeedCalculator!!, 1, 1, TimeUnit.SECONDS)
            }
            peer!!.addBlocksDownloadedEventListener(Threading.SAME_THREAD, chainDownloadSpeedCalculator)

            // startBlockChainDownload will setDownloadData(true) on itself automatically.
            peer.startBlockChainDownload()
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns a future that is triggered when the number of connected peers is equal to the given number of
     * peers. By using this with [org.bitcoinj.core.PeerGroup.getMaxConnections] you can wait until the
     * network is fully online. To block immediately, just call get() on the result. Just calls
     * [.waitForPeersOfVersion] with zero as the protocol version.
     *
     * @param numPeers How many peers to wait for.
     * @return a future that will be triggered when the number of connected peers >= numPeers
     */
    fun waitForPeers(numPeers: Int): ListenableFuture<List<Peer>> {
        return waitForPeersOfVersion(numPeers, 0)
    }

    /**
     * Returns a future that is triggered when there are at least the requested number of connected peers that support
     * the given protocol version or higher. To block immediately, just call get() on the result.
     *
     * @param numPeers How many peers to wait for.
     * @param protocolVersion The protocol version the awaited peers must implement (or better).
     * @return a future that will be triggered when the number of connected peers implementing protocolVersion or higher >= numPeers
     */
    fun waitForPeersOfVersion(numPeers: Int, protocolVersion: Long): ListenableFuture<List<Peer>> {
        val foundPeers = findPeersOfAtLeastVersion(protocolVersion)
        if (foundPeers.size >= numPeers) {
            return Futures.immediateFuture(foundPeers)
        }
        val future = SettableFuture.create<List<Peer>>()
        addConnectedEventListener(object : PeerConnectedEventListener {
            override fun onPeerConnected(peer: Peer, peerCount: Int) {
                val peers = findPeersOfAtLeastVersion(protocolVersion)
                if (peers.size >= numPeers) {
                    future.set(peers)
                    removeConnectedEventListener(this)
                }
            }
        })
        return future
    }

    /**
     * Returns an array list of peers that implement the given protocol version or better.
     */
    fun findPeersOfAtLeastVersion(protocolVersion: Long): List<Peer> {
        lock.lock()
        try {
            val results = ArrayList<Peer>(peers.size)
            for (peer in peers)
                if (peer.peerVersionMessage!!.clientVersion >= protocolVersion)
                    results.add(peer)
            return results
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns a future that is triggered when there are at least the requested number of connected peers that support
     * the given protocol version or higher. To block immediately, just call get() on the result.
     *
     * @param numPeers How many peers to wait for.
     * @param mask An integer representing a bit mask that will be ANDed with the peers advertised service masks.
     * @return a future that will be triggered when the number of connected peers implementing protocolVersion or higher >= numPeers
     */
    fun waitForPeersWithServiceMask(numPeers: Int, mask: Int): ListenableFuture<List<Peer>> {
        lock.lock()
        try {
            val foundPeers = findPeersWithServiceMask(mask)
            if (foundPeers.size >= numPeers)
                return Futures.immediateFuture(foundPeers)
            val future = SettableFuture.create<List<Peer>>()
            addConnectedEventListener(object : PeerConnectedEventListener {
                override fun onPeerConnected(peer: Peer, peerCount: Int) {
                    val peers = findPeersWithServiceMask(mask)
                    if (peers.size >= numPeers) {
                        future.set(peers)
                        removeConnectedEventListener(this)
                    }
                }
            })
            return future
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns an array list of peers that match the requested service bit mask.
     */
    fun findPeersWithServiceMask(mask: Int): List<Peer> {
        lock.lock()
        try {
            val results = ArrayList<Peer>(peers.size)
            for (peer in peers)
                if (peer.peerVersionMessage!!.localServices and mask == mask.toLong())
                    results.add(peer)
            return results
        } finally {
            lock.unlock()
        }
    }

    /**
     * Returns the number of connections that are required before transactions will be broadcast. If there aren't
     * enough, [PeerGroup.broadcastTransaction] will wait until the minimum number is reached so
     * propagation across the network can be observed. If no value has been set using
     * [PeerGroup.setMinBroadcastConnections] a default of 80% of whatever
     * [org.bitcoinj.core.PeerGroup.getMaxConnections] returns is used.
     */
    fun getMinBroadcastConnections(): Int {
        lock.lock()
        try {
            if (minBroadcastConnections == 0) {
                val max = getMaxConnections()
                return if (max <= 1)
                    max
                else
                    Math.round(getMaxConnections() * 0.8).toInt()
            }
            return minBroadcastConnections
        } finally {
            lock.unlock()
        }
    }

    /**
     * See [org.bitcoinj.core.PeerGroup.getMinBroadcastConnections].
     */
    fun setMinBroadcastConnections(value: Int) {
        lock.lock()
        try {
            minBroadcastConnections = value
        } finally {
            lock.unlock()
        }
    }

    /**
     * Calls [PeerGroup.broadcastTransaction] with getMinBroadcastConnections() as the number
     * of connections to wait for before commencing broadcast.
     */
    override fun broadcastTransaction(tx: Transaction): TransactionBroadcast {
        return broadcastTransaction(tx, Math.max(1, getMinBroadcastConnections()))
    }

    /**
     *
     * Given a transaction, sends it un-announced to one peer and then waits for it to be received back from other
     * peers. Once all connected peers have announced the transaction, the future available via the
     * [org.bitcoinj.core.TransactionBroadcast.future] method will be completed. If anything goes
     * wrong the exception will be thrown when get() is called, or you can receive it via a callback on the
     * [ListenableFuture]. This method returns immediately, so if you want it to block just call get() on the
     * result.
     *
     *
     * Note that if the PeerGroup is limited to only one connection (discovery is not activated) then the future
     * will complete as soon as the transaction was successfully written to that peer.
     *
     *
     * The transaction won't be sent until there are at least minConnections active connections available.
     * A good choice for proportion would be between 0.5 and 0.8 but if you want faster transmission during initial
     * bringup of the peer group you can lower it.
     *
     *
     * The returned [org.bitcoinj.core.TransactionBroadcast] object can be used to get progress feedback,
     * which is calculated by watching the transaction propagate across the network and be announced by peers.
     */
    fun broadcastTransaction(tx: Transaction, minConnections: Int): TransactionBroadcast {
        // If we don't have a record of where this tx came from already, set it to be ourselves so Peer doesn't end up
        // redownloading it from the network redundantly.
        if (tx.confidence.source == TransactionConfidence.Source.UNKNOWN) {
            log.info("Transaction source unknown, setting to SELF: {}", tx.hashAsString)
            tx.confidence.source = TransactionConfidence.Source.SELF
        }
        val broadcast = TransactionBroadcast(this, tx)
        broadcast.setMinConnections(minConnections)
        // Send the TX to the wallet once we have a successful broadcast.
        Futures.addCallback(broadcast.future(), object : FutureCallback<Transaction> {
            override fun onSuccess(transaction: Transaction?) {
                runningBroadcasts.remove(broadcast)
                // OK, now tell the wallet about the transaction. If the wallet created the transaction then
                // it already knows and will ignore this. If it's a transaction we received from
                // somebody else via a side channel and are now broadcasting, this will put it into the
                // wallet now we know it's valid.
                for (wallet in wallets) {
                    // Assumption here is there are no dependencies of the created transaction.
                    //
                    // We may end up with two threads trying to do this in parallel - the wallet will
                    // ignore whichever one loses the race.
                    try {
                        wallet.receivePending(transaction, null)
                    } catch (e: VerificationException) {
                        throw RuntimeException(e)   // Cannot fail to verify a tx we created ourselves.
                    }

                }
            }

            override fun onFailure(throwable: Throwable) {
                // This can happen if we get a reject message from a peer.
                runningBroadcasts.remove(broadcast)
            }
        })
        // Keep a reference to the TransactionBroadcast object. This is important because otherwise, the entire tree
        // of objects we just created would become garbage if the user doesn't hold on to the returned future, and
        // eventually be collected. This in turn could result in the transaction not being committed to the wallet
        // at all.
        runningBroadcasts.add(broadcast)
        broadcast.broadcast()
        return broadcast
    }

    /**
     * Returns the period between pings for an individual peer. Setting this lower means more accurate and timely ping
     * times are available via [org.bitcoinj.core.Peer.getLastPingTime] but it increases load on the
     * remote node. It defaults to [PeerGroup.DEFAULT_PING_INTERVAL_MSEC].
     */
    fun getPingIntervalMsec(): Long {
        lock.lock()
        try {
            return pingIntervalMsec
        } finally {
            lock.unlock()
        }
    }

    /**
     * Sets the period between pings for an individual peer. Setting this lower means more accurate and timely ping
     * times are available via [org.bitcoinj.core.Peer.getLastPingTime] but it increases load on the
     * remote node. It defaults to [PeerGroup.DEFAULT_PING_INTERVAL_MSEC].
     * Setting the value to be <= 0 disables pinging entirely, although you can still request one yourself
     * using [org.bitcoinj.core.Peer.ping].
     */
    fun setPingIntervalMsec(pingIntervalMsec: Long) {
        lock.lock()
        try {
            this.pingIntervalMsec = pingIntervalMsec
            val task = vPingTask
            task?.cancel(false)
            setupPinging()
        } finally {
            lock.unlock()
        }
    }

    /**
     * Given a list of Peers, return a Peer to be used as the download peer. If you don't want PeerGroup to manage
     * download peer statuses for you, just override this and always return null.
     */
    protected fun selectDownloadPeer(peers: List<Peer>): Peer? {
        // Characteristics to select for in order of importance:
        //  - Chain height is reasonable (majority of nodes)
        //  - High enough protocol version for the features we want (but we'll settle for less)
        //  - Randomly, to try and spread the load.
        if (peers.isEmpty())
            return null
        // Make sure we don't select a peer that is behind/synchronizing itself.
        val mostCommonChainHeight = getMostCommonChainHeight(peers)
        val candidates = ArrayList<Peer>()
        for (peer in peers) {
            if (peer.bestHeight == mostCommonChainHeight.toLong()) candidates.add(peer)
        }
        // Of the candidates, find the peers that meet the minimum protocol version we want to target. We could select
        // the highest version we've seen on the assumption that newer versions are always better but we don't want to
        // zap peers if they upgrade early. If we can't find any peers that have our preferred protocol version or
        // better then we'll settle for the highest we found instead.
        var highestVersion = 0
        var preferredVersion = 0
        // If/when PREFERRED_VERSION is not equal to vMinRequiredProtocolVersion, reenable the last test in PeerGroupTest.downloadPeerSelection
        val PREFERRED_VERSION = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.BLOOM_FILTER)
        for (peer in candidates) {
            highestVersion = Math.max(peer.peerVersionMessage!!.clientVersion, highestVersion)
            preferredVersion = Math.min(highestVersion, PREFERRED_VERSION)
        }
        val candidates2 = ArrayList<Peer>(candidates.size)
        for (peer in candidates) {
            if (peer.peerVersionMessage!!.clientVersion >= preferredVersion) {
                candidates2.add(peer)
            }
        }
        val index = (Math.random() * candidates2.size).toInt()
        return candidates2[index]
    }

    /**
     * Returns the currently selected download peer. Bear in mind that it may have changed as soon as this method
     * returns. Can return null if no peer was selected.
     */
    fun getDownloadPeer(): Peer? {
        lock.lock()
        try {
            return downloadPeer
        } finally {
            lock.unlock()
        }
    }

    /** See [.setUseLocalhostPeerWhenPossible]  */
    fun getUseLocalhostPeerWhenPossible(): Boolean {
        lock.lock()
        try {
            return useLocalhostPeerWhenPossible
        } finally {
            lock.unlock()
        }
    }

    /**
     * When true (the default), PeerGroup will attempt to connect to a Bitcoin node running on localhost before
     * attempting to use the P2P network. If successful, only localhost will be used. This makes for a simple
     * and easy way for a user to upgrade a bitcoinj based app running in SPV mode to fully validating security.
     */
    fun setUseLocalhostPeerWhenPossible(useLocalhostPeerWhenPossible: Boolean) {
        lock.lock()
        try {
            this.useLocalhostPeerWhenPossible = useLocalhostPeerWhenPossible
        } finally {
            lock.unlock()
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(PeerGroup::class.java!!)
        /**
         * The default number of connections to the p2p network the library will try to build. This is set to 12 empirically.
         * It used to be 4, but because we divide the connection pool in two for broadcasting transactions, that meant we
         * were only sending transactions to two peers and sometimes this wasn't reliable enough: transactions wouldn't
         * get through.
         */
        val DEFAULT_CONNECTIONS = 12
        private val TOR_TIMEOUT_SECONDS = 60
        private val DEFAULT_PEER_DISCOVERY_TIMEOUT_MILLIS: Long = 5000

        /** How many milliseconds to wait after receiving a pong before sending another ping.  */
        val DEFAULT_PING_INTERVAL_MSEC: Long = 2000

        /**
         * The default Bloom filter false positive rate, which is selected to be extremely low such that you hardly ever
         * download false positives. This provides maximum performance. Although this default can be overridden to push
         * the FP rate higher, due to [
 * various complexities](https://groups.google.com/forum/#!msg/bitcoinj/Ys13qkTwcNg/9qxnhwnkeoIJ) there are still ways a remote peer can deanonymize the users wallet. This is why the
         * FP rate is chosen for performance rather than privacy. If a future version of bitcoinj fixes the known
         * de-anonymization attacks this FP rate may rise again (or more likely, become expressed as a bandwidth allowance).
         */
        val DEFAULT_BLOOM_FILTER_FP_RATE = 0.00001
        /** Maximum increase in FP rate before forced refresh of the bloom filter  */
        val MAX_FP_RATE_INCREASE = 10.0

        /** The default timeout between when a connection attempt begins and version message exchange completes  */
        val DEFAULT_CONNECT_TIMEOUT_MILLIS = 5000

        /** See [.newWithTor]  */
        @Throws(TimeoutException::class)
        fun newWithTor(params: NetworkParameters, chain: AbstractBlockChain?, torClient: TorClient): PeerGroup {
            return newWithTor(Context.getOrCreate(params), chain, torClient)
        }

        /**
         *
         * Creates a PeerGroup that accesses the network via the Tor network. The provided TorClient is used so you can
         * preconfigure it beforehand. It should not have been already started. You can just use "new TorClient()" if
         * you don't have any particular configuration requirements.
         *
         *
         * If running on the Oracle JDK the unlimited strength jurisdiction checks will also be overridden,
         * as they no longer apply anyway and can cause startup failures due to the requirement for AES-256.
         *
         *
         * The user does not need any additional software for this: it's all pure Java. As of April 2014 **this mode
         * is experimental**.
         *
         * @param doDiscovery if true, DNS or HTTP peer discovery will be performed via Tor: this is almost always what you want.
         * @throws java.util.concurrent.TimeoutException if Tor fails to start within 20 seconds.
         */
        @Throws(TimeoutException::class)
        @JvmOverloads
        fun newWithTor(context: Context, chain: AbstractBlockChain?, torClient: TorClient, doDiscovery: Boolean = true): PeerGroup {
            checkNotNull(torClient)
            DRMWorkaround.maybeDisableExportControls()
            val manager = BlockingClientManager(torClient.socketFactory)
            val CONNECT_TIMEOUT_MSEC = TOR_TIMEOUT_SECONDS * 1000
            manager.setConnectTimeoutMillis(CONNECT_TIMEOUT_MSEC)
            val result = PeerGroup(context, chain, manager, torClient)
            result.setConnectTimeoutMillis(CONNECT_TIMEOUT_MSEC)

            if (doDiscovery) {
                val params = context.params
                val httpSeeds = params.httpSeeds
                if (httpSeeds.size > 0) {
                    // Use HTTP discovery when Tor is active and there is a Cartographer seed, for a much needed speed boost.
                    val httpClient = OkHttpClient()
                    httpClient.socketFactory = torClient.socketFactory
                    val discoveries = Lists.newArrayList<PeerDiscovery>()
                    for (httpSeed in httpSeeds)
                        discoveries.add(HttpDiscovery(params, httpSeed, httpClient))
                    result.addPeerDiscovery(MultiplexingDiscovery(params, discoveries))
                } else {
                    result.addPeerDiscovery(TorDiscovery(params, torClient))
                }
            }
            return result
        }

        /**
         * Register a data event listener against a single peer (i.e. for blockchain
         * download). Handling registration/deregistration on peer death/add is
         * outside the scope of these methods.
         */
        private fun addDataEventListenerToPeer(executor: Executor, peer: Peer, downloadListener: PeerDataEventListener) {
            peer.addBlocksDownloadedEventListener(executor, downloadListener)
            peer.addChainDownloadStartedEventListener(executor, downloadListener)
            peer.addGetDataEventListener(executor, downloadListener)
            peer.addPreMessageReceivedEventListener(executor, downloadListener)
        }

        /**
         * Remove a registered data event listener against a single peer (i.e. for
         * blockchain download). Handling registration/deregistration on peer death/add is
         * outside the scope of these methods.
         */
        private fun removeDataEventListenerFromPeer(peer: Peer, listener: PeerDataEventListener) {
            peer.removeBlocksDownloadedEventListener(listener)
            peer.removeChainDownloadStartedEventListener(listener)
            peer.removeGetDataEventListener(listener)
            peer.removePreMessageReceivedEventListener(listener)
        }

        /**
         * Returns most commonly reported chain height from the given list of [Peer]s.
         * If multiple heights are tied, the highest is returned. If no peers are connected, returns zero.
         */
        fun getMostCommonChainHeight(peers: List<Peer>): Int {
            if (peers.isEmpty())
                return 0
            val heights = ArrayList<Int>(peers.size)
            for (peer in peers) heights.add(peer.bestHeight.toInt())
            return Utils.maxOfMostFreq(heights)
        }
    }
}
/** See [.PeerGroup]  */
/**
 * Creates a PeerGroup with the given context. No chain is provided so this node will report its chain height
 * as zero to other peers. This constructor is useful if you just want to explore the network but aren't interested
 * in downloading block data.
 */
/**
 * Creates a PeerGroup for the given context and chain. Blocks will be passed to the chain as they are broadcast
 * and downloaded. This is probably the constructor you want to use.
 */
/**
 *
 * Creates a PeerGroup that accesses the network via the Tor network. The provided TorClient is used so you can
 * preconfigure it beforehand. It should not have been already started. You can just use "new TorClient()" if
 * you don't have any particular configuration requirements.
 *
 *
 * Peer discovery is automatically configured to use DNS seeds resolved via a random selection of exit nodes.
 * If running on the Oracle JDK the unlimited strength jurisdiction checks will also be overridden,
 * as they no longer apply anyway and can cause startup failures due to the requirement for AES-256.
 *
 *
 * The user does not need any additional software for this: it's all pure Java. As of April 2014 **this mode
 * is experimental**.
 *
 * @throws TimeoutException if Tor fails to start within 20 seconds.
 */
/**
 * Sets information that identifies this software to remote nodes. This is a convenience wrapper for creating
 * a new [VersionMessage], calling [VersionMessage.appendToSubVer] on it,
 * and then calling [PeerGroup.setVersionMessage] on the result of that. See the docs for
 * [VersionMessage.appendToSubVer] for information on what the fields should contain.
 */
