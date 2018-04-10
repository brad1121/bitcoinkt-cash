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

import com.google.common.base.Objects
import org.bitcoinj.core.Block
import org.bitcoinj.core.StoredBlock
import org.bitcoinj.core.VerificationException
import org.bitcoinj.net.discovery.*
import org.bitcoinj.params.*
import org.bitcoinj.script.*
import org.bitcoinj.store.BlockStore
import org.bitcoinj.store.BlockStoreException

import org.bitcoinj.utils.MonetaryFormat

import javax.annotation.*
import java.io.*
import java.math.*
import java.util.*

import org.bitcoinj.core.Coin.*
import org.bitcoinj.utils.VersionTally

/**
 *
 * NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.
 *
 *
 * This is an abstract class, concrete instantiations can be found in the params package. There are four:
 * one for the main network ([MainNetParams]), one for the public test network, and two others that are
 * intended for unit testing and local app development purposes. Although this class contains some aliases for
 * them, you are encouraged to call the static get() methods on each specific params class directly.
 */
abstract class NetworkParameters protected constructor() {

    // TODO: Seed nodes should be here as well.

    /**
     *
     * Genesis block for this chain.
     *
     *
     * The first block in every chain is a well known constant shared between all Bitcoin implemenetations. For a
     * block to be valid, it must be eventually possible to work backwards to the genesis block by following the
     * prevBlockHash pointers in the block headers.
     *
     *
     * The genesis blocks for both test and main networks contain the timestamp of when they were created,
     * and a message in the coinbase transaction. It says, *"The Times 03/Jan/2009 Chancellor on brink of second
     * bailout for banks"*.
     */
    var genesisBlock: Block
    /** Maximum target represents the easiest allowable proof of work.  */
    var maxTarget: BigInteger? = null
    /** Default TCP port on which to connect to nodes.  */
    var port: Int = 0
        protected set
    /** The header bytes that identify the start of a packet on this network.  */
    var packetMagic: Long = 0
        protected set  // Indicates message origin network and is used to seek to the next message when stream state is unknown.
    /**
     * First byte of a base58 encoded address. See [org.bitcoinj.core.Address]. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    var addressHeader: Int = 0
        protected set
    /**
     * First byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
     */
    var p2SHHeader: Int = 0
    /** First byte of a base58 encoded dumped private key. See [org.bitcoinj.core.DumpedPrivateKey].  */
    var dumpedPrivateKeyHeader: Int = 0
        protected set
    /** How many blocks pass between difficulty adjustment periods. Bitcoin standardises this to be 2015.  */
    var interval: Int = 0
        protected set // blocks per difficulty cycle
    /**
     * How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
     * significantly different from this value, the network difficulty formula will produce a different value. Both
     * test and main Bitcoin networks use 2 weeks (1209600 seconds).
     */
    var targetTimespan: Int = 0
        protected set
    /**
     * The key used to sign [org.bitcoinj.core.AlertMessage]s. You can use [org.bitcoinj.core.ECKey.verify] to verify
     * signatures using it.
     */
    var alertSigningKey: ByteArray
        protected set
    /** Returns the 4 byte header for BIP32 (HD) wallet - public key part.  */
    var bip32HeaderPub: Int = 0
        protected set
    /** Returns the 4 byte header for BIP32 (HD) wallet - private key part.  */
    var bip32HeaderPriv: Int = 0
        protected set

    /** Used to check majorities for block version upgrade  */
    /**
     * The number of blocks in the last [] blocks
     * at which to trigger a notice to the user to upgrade their client, where
     * the client does not understand those blocks.
     */
    var majorityEnforceBlockUpgrade: Int = 0
        protected set
    /**
     * The number of blocks in the last [] blocks
     * at which to enforce the requirement that all new blocks are of the
     * newer type (i.e. outdated blocks are rejected).
     */
    var majorityRejectBlockOutdated: Int = 0
        protected set
    /**
     * The sampling window from which the version numbers of blocks are taken
     * in order to determine if a new block version is now the majority.
     */
    var majorityWindow: Int = 0
        protected set

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    /**
     * A Java package style string acting as unique ID for these parameters
     */
    var id: String? = null

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    var spendableCoinbaseDepth: Int = 0
        protected set
    var subsidyDecreaseBlockCount: Int = 0
        protected set

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    var acceptableAddressCodes: IntArray? = null
        protected set
    /** Returns DNS names that when resolved, give IP addresses of active peers.  */
    var dnsSeeds: Array<String>? = null
        protected set
    /** Returns IP address of active peers.  */
    var addrSeeds: IntArray? = null
        protected set
    /** Returns discovery objects for seeds implementing the Cartographer protocol. See [org.bitcoinj.net.discovery.HttpDiscovery] for more info.  */
    var httpSeeds = arrayOf<HttpDiscovery.Details>()
        protected set
    protected var checkpoints: Map<Int, Sha256Hash> = HashMap()
    @Transient var defaultSerializer: MessageSerializer? = null
        get(): MessageSerializer? {
        // Construct a default serializer if we don't have one
        if (null == this.defaultSerializer) {
            // Don't grab a lock unless we absolutely need it
            synchronized(this) {
                // Now we have a lock, double check there's still no serializer
                // and create one if so.
                if (null == this.defaultSerializer) {
                    // As the serializers are intended to be immutable, creating
                    // two due to a race condition should not be a problem, however
                    // to be safe we ensure only one exists for each network.
                    this.defaultSerializer = getSerializer(false)
                }
            }
        }
        return defaultSerializer
        }
        protected set

    abstract val paymentProtocolId: String

    /**
     * Returns the number of coins that will be produced in total, on this
     * network. Where not applicable, a very large number of coins is returned
     * instead (i.e. the main coin issue for Dogecoin).
     */
    abstract val maxMoney: Coin

    /**
     * Any standard (ie pay-to-address) output smaller than this value will
     * most likely be rejected by the network.
     */
    abstract val minNonDustOutput: Coin

    /**
     * The monetary object for this currency.
     */
    abstract val monetaryFormat: MonetaryFormat

    /**
     * Scheme part for URIs, for example "bitcoin".
     */
    abstract val uriScheme: String

    init {
        alertSigningKey = SATOSHI_KEY
        genesisBlock = createGenesis(this)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        return if (o == null || javaClass != o.javaClass) false else id == (o as NetworkParameters).id
    }

    override fun hashCode(): Int {
        return Objects.hashCode(id)
    }

    /**
     * Throws an exception if the block's difficulty is not correct.
     *
     * @throws VerificationException if the block's difficulty is not correct.
     */
    @Throws(VerificationException::class, BlockStoreException::class)
    abstract fun checkDifficultyTransitions(storedPrev: StoredBlock, next: Block, blockStore: BlockStore, blockChain: AbstractBlockChain)

    /**
     * Returns true if the block height is either not a checkpoint, or is a checkpoint and the hash matches.
     */
    fun passesCheckpoint(height: Int, hash: Sha256Hash): Boolean {
        val checkpointHash = checkpoints[height]
        return checkpointHash == null || checkpointHash == hash
    }

    /**
     * Returns true if the given height has a recorded checkpoint.
     */
    fun isCheckpoint(height: Int): Boolean {
        val checkpointHash = checkpoints[height]
        return checkpointHash != null
    }

    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks.
     */
    open fun allowEmptyPeerChain(): Boolean {
        return true
    }

    /**
     * Returns whether this network has a maximum number of coins (finite supply) or
     * not. Always returns true for Bitcoin, but exists to be overriden for other
     * networks.
     */
    abstract fun hasMaxMoney(): Boolean

    /**
     * Construct and return a custom serializer.
     */
    abstract fun getSerializer(parseRetain: Boolean): BitcoinSerializer

    /**
     * The flags indicating which block validation tests should be applied to
     * the given block. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     *
     * @param block block to determine flags for.
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     */
    fun getBlockVerificationFlags(block: Block,
                                  tally: VersionTally, height: Int?): EnumSet<Block.VerifyFlag> {
        val flags = EnumSet.noneOf<Block.VerifyFlag>(Block.VerifyFlag::class.java)

        if (block.isBIP34) {
            val count = tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP34)
            if (null != count && count >= majorityEnforceBlockUpgrade) {
                flags.add(Block.VerifyFlag.HEIGHT_IN_COINBASE)
            }
        }
        return flags
    }

    /**
     * The flags indicating which script validation tests should be applied to
     * the given transaction. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     *
     * @param block block the transaction belongs to.
     * @param transaction to determine flags for.
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     */
    fun getTransactionVerificationFlags(block: Block,
                                        transaction: Transaction, tally: VersionTally, height: Int?): EnumSet<Script.VerifyFlag> {
        val verifyFlags = EnumSet.noneOf<Script.VerifyFlag>(Script.VerifyFlag::class.java)
        if (block.timeSeconds >= NetworkParameters.BIP16_ENFORCE_TIME)
            verifyFlags.add(Script.VerifyFlag.P2SH)

        // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
        // blocks, when 75% of the network has upgraded:
        if (block.version >= Block.BLOCK_VERSION_BIP65 && tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP65) > this.majorityEnforceBlockUpgrade) {
            verifyFlags.add(Script.VerifyFlag.CHECKLOCKTIMEVERIFY)
        }

        return verifyFlags
    }

    abstract fun getProtocolVersionNum(version: ProtocolVersion): Int

    enum class ProtocolVersion private constructor(val bitcoinProtocolVersion: Int) {
        MINIMUM(70000),
        PONG(60001),
        BLOOM_FILTER(70000),
        CURRENT(70013)
    }

    companion object {
        /**
         * The alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
         */
        val SATOSHI_KEY = Utils.HEX.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284")

        /** The string returned by getId() for the main, production network where people trade things.  */
        val ID_MAINNET = "org.bitcoin.production"
        /** The string returned by getId() for the testnet.  */
        val ID_TESTNET = "org.bitcoin.test"
        /** The string returned by getId() for regtest mode.  */
        val ID_REGTEST = "org.bitcoin.regtest"
        /** Unit test network.  */
        val ID_UNITTESTNET = "org.bitcoinj.unittest"

        /** The string used by the payment protocol to represent the main net.  */
        val PAYMENT_PROTOCOL_ID_MAINNET = "main"
        /** The string used by the payment protocol to represent the test net.  */
        val PAYMENT_PROTOCOL_ID_TESTNET = "test"
        /** The string used by the payment protocol to represent unit testing (note that this is non-standard).  */
        val PAYMENT_PROTOCOL_ID_UNIT_TESTS = "unittest"
        val PAYMENT_PROTOCOL_ID_REGTEST = "regtest"

        private fun createGenesis(n: NetworkParameters): Block {
            val genesisBlock = Block(n, Block.BLOCK_VERSION_GENESIS)
            val t = Transaction(n)
            try {
                // A script containing the difficulty bits and the following message:
                //
                //   "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
                val bytes = Utils.HEX.decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73")
                t.addInput(TransactionInput(n, t, bytes))
                val scriptPubKeyBytes = ByteArrayOutputStream()
                Script.writeBytes(scriptPubKeyBytes, Utils.HEX.decode("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"))
                scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG)
                t.addOutput(TransactionOutput(n, t, Coin.FIFTY_COINS, scriptPubKeyBytes.toByteArray()))
            } catch (e: Exception) {
                // Cannot happen.
                throw RuntimeException(e)
            }

            genesisBlock.addTransaction(t)
            return genesisBlock
        }

        val TARGET_TIMESPAN = 14 * 24 * 60 * 60  // 2 weeks per difficulty cycle, on average.
        val TARGET_SPACING = 10 * 60  // 10 minutes per block.
        val INTERVAL = TARGET_TIMESPAN / TARGET_SPACING // blocks per difficulty cycle

        /**
         * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
         * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
         * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
         */
        val BIP16_ENFORCE_TIME = 1333238400

        /**
         * The maximum number of coins to be generated
         */
        val MAX_COINS: Long = 21000000

        /**
         * The maximum money to be generated
         */
        val MAX_MONEY = Coin.COIN.multiply(MAX_COINS)

        /** Alias for TestNet3Params.get(), use that instead.  */
        @Deprecated("")
        fun testNet(): NetworkParameters {
            return TestNet3Params.get()
        }

        /** Alias for TestNet2Params.get(), use that instead.  */
        @Deprecated("")
        fun testNet2(): NetworkParameters {
            return TestNet2Params.get()
        }

        /** Alias for TestNet3Params.get(), use that instead.  */
        @Deprecated("")
        fun testNet3(): NetworkParameters {
            return TestNet3Params.get()
        }

        /** Alias for MainNetParams.get(), use that instead  */
        @Deprecated("")
        fun prodNet(): NetworkParameters {
            return MainNetParams.get()
        }

        /** Returns a testnet params modified to allow any difficulty target.  */
        @Deprecated("")
        fun unitTests(): NetworkParameters {
            return UnitTestParams.get()
        }

        /** Returns a standard regression test params (similar to unitTests)  */
        @Deprecated("")
        fun regTests(): NetworkParameters {
            return RegTestParams.get()
        }

        /** Returns the network parameters for the given string ID or NULL if not recognized.  */
        fun fromID(id: String): NetworkParameters? {
            return if (id == ID_MAINNET) {
                MainNetParams.get()
            } else if (id == ID_TESTNET) {
                TestNet3Params.get()
            } else if (id == ID_UNITTESTNET) {
                UnitTestParams.get()
            } else if (id == ID_REGTEST) {
                RegTestParams.get()
            } else {
                null
            }
        }

        /** Returns the network parameters for the given string paymentProtocolID or NULL if not recognized.  */
        fun fromPmtProtocolID(pmtProtocolId: String): NetworkParameters? {
            return if (pmtProtocolId == PAYMENT_PROTOCOL_ID_MAINNET) {
                MainNetParams.get()
            } else if (pmtProtocolId == PAYMENT_PROTOCOL_ID_TESTNET) {
                TestNet3Params.get()
            } else if (pmtProtocolId == PAYMENT_PROTOCOL_ID_UNIT_TESTS) {
                UnitTestParams.get()
            } else if (pmtProtocolId == PAYMENT_PROTOCOL_ID_REGTEST) {
                RegTestParams.get()
            } else {
                null
            }
        }
    }
}
