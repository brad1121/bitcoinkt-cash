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

package org.bitcoinj.core

import com.google.common.base.Objects
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Locale

/**
 *
 * A VersionMessage holds information exchanged during connection setup with another peer. Most of the fields are not
 * particularly interesting. The subVer field, since BIP 14, acts as a User-Agent string would. You can and should
 * append to or change the subVer for your own software so other implementations can identify it, and you can look at
 * the subVer field received from other nodes to see what they are running.
 *
 *
 * After creating yourself a VersionMessage, you can pass it to [PeerGroup.setVersionMessage]
 * to ensure it will be used for each new connection.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class VersionMessage : Message {

    /**
     * The version number of the protocol spoken.
     */
    var clientVersion: Int = 0
    /**
     * Flags defining what optional services are supported.
     */
    var localServices: Long = 0
    /**
     * What the other side believes the current time to be, in seconds.
     */
    var time: Long = 0
    /**
     * What the other side believes the address of this program is. Not used.
     */
    var myAddr: PeerAddress
    /**
     * What the other side believes their own address is. Not used.
     */
    var theirAddr: PeerAddress
    /**
     * User-Agent as defined in [BIP 14](https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki).
     * Bitcoin Core sets it to something like "/Satoshi:0.9.1/".
     */
    var subVer: String
    /**
     * How many blocks are in the chain, according to the other side.
     */
    var bestHeight: Long = 0
    /**
     * Whether or not to relay tx invs before a filter is received.
     * See [BIP 37](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#extensions-to-existing-messages).
     */
    var relayTxesBeforeFilter: Boolean = false

    /**
     * Returns true if the clientVersion field is >= Pong.MIN_PROTOCOL_VERSION. If it is then ping() is usable.
     */
    val isPingPongSupported: Boolean
        get() = clientVersion >= params!!.getProtocolVersionNum(NetworkParameters.ProtocolVersion.PONG)

    /**
     * Returns true if the clientVersion field is >= FilteredBlock.MIN_PROTOCOL_VERSION. If it is then Bloom filtering
     * is available and the memory pool of the remote peer will be queried when the downloadData property is true.
     */
    val isBloomFilteringSupported: Boolean
        get() = clientVersion >= params!!.getProtocolVersionNum(NetworkParameters.ProtocolVersion.BLOOM_FILTER)

    /** Returns true if the protocol version and service bits both indicate support for the getutxos message.  */
    val isGetUTXOsSupported: Boolean
        get() = clientVersion >= GetUTXOsMessage.MIN_PROTOCOL_VERSION && localServices and NODE_GETUTXOS == NODE_GETUTXOS.toLong()

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray) : super(params, payload, 0) {
    }

    // It doesn't really make sense to ever lazily parse a version message or to retain the backing bytes.
    // If you're receiving this on the wire you need to check the protocol version and it will never need to be sent
    // back down the wire.

    constructor(params: NetworkParameters, newBestHeight: Int) : super(params) {
        clientVersion = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT)
        localServices = 0
        time = System.currentTimeMillis() / 1000
        // Note that the Bitcoin Core doesn't do anything with these, and finding out your own external IP address
        // is kind of tricky anyway, so we just put nonsense here for now.
        try {
            // We hard-code the IPv4 localhost address here rather than use InetAddress.getLocalHost() because some
            // mobile phones have broken localhost DNS entries, also, this is faster.
            val localhost = byteArrayOf(127, 0, 0, 1)
            myAddr = PeerAddress(InetAddress.getByAddress(localhost), params.port, 0)
            theirAddr = PeerAddress(InetAddress.getByAddress(localhost), params.port, 0)
        } catch (e: UnknownHostException) {
            throw RuntimeException(e)  // Cannot happen (illegal IP length).
        }

        subVer = LIBRARY_SUBVER
        bestHeight = newBestHeight.toLong()
        relayTxesBeforeFilter = true

        length = 85
        if (protocolVersion > 31402)
            length += 8
        length += VarInt.sizeOf(subVer.length.toLong()) + subVer.length
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        clientVersion = readUint32().toInt()
        localServices = readUint64().toLong()
        time = readUint64().toLong()
        myAddr = PeerAddress(params, payload, cursor, 0)
        cursor += myAddr.messageSize
        theirAddr = PeerAddress(params, payload, cursor, 0)
        cursor += theirAddr.messageSize
        // uint64 localHostNonce  (random data)
        // We don't care about the localhost nonce. It's used to detect connecting back to yourself in cases where
        // there are NATs and proxies in the way. However we don't listen for inbound connections so it's irrelevant.
        readUint64()
        try {
            // Initialize default values for flags which may not be sent by old nodes
            subVer = ""
            bestHeight = 0
            relayTxesBeforeFilter = true
            if (!hasMoreBytes())
                return
            //   string subVer  (currently "")
            subVer = readStr()
            if (!hasMoreBytes())
                return
            //   int bestHeight (size of known block chain).
            bestHeight = readUint32()
            if (!hasMoreBytes())
                return
            relayTxesBeforeFilter = readBytes(1)[0].toInt() != 0
        } finally {
            length = cursor - offset
        }
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(buf: OutputStream) {
        Utils.uint32ToByteStreamLE(clientVersion.toLong(), buf)
        Utils.uint32ToByteStreamLE(localServices, buf)
        Utils.uint32ToByteStreamLE(localServices shr 32, buf)
        Utils.uint32ToByteStreamLE(time, buf)
        Utils.uint32ToByteStreamLE(time shr 32, buf)
        try {
            // My address.
            myAddr.bitcoinSerialize(buf)
            // Their address.
            theirAddr.bitcoinSerialize(buf)
        } catch (e: UnknownHostException) {
            throw RuntimeException(e)  // Can't happen.
        } catch (e: IOException) {
            throw RuntimeException(e)  // Can't happen.
        }

        // Next up is the "local host nonce", this is to detect the case of connecting
        // back to yourself. We don't care about this as we won't be accepting inbound
        // connections.
        Utils.uint32ToByteStreamLE(0, buf)
        Utils.uint32ToByteStreamLE(0, buf)
        // Now comes subVer.
        val subVerBytes = subVer.toByteArray(charset("UTF-8"))
        buf.write(VarInt(subVerBytes.size.toLong()).encode())
        buf.write(subVerBytes)
        // Size of known block chain.
        Utils.uint32ToByteStreamLE(bestHeight, buf)
        buf.write(if (relayTxesBeforeFilter) 1 else 0)
    }

    /**
     * Returns true if the version message indicates the sender has a full copy of the block chain,
     * or if it's running in client mode (only has the headers).
     */
    fun hasBlockChain(): Boolean {
        return localServices and NODE_NETWORK == NODE_NETWORK.toLong()
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as VersionMessage?
        return other!!.bestHeight == bestHeight &&
                other.clientVersion == clientVersion &&
                other.localServices == localServices &&
                other.time == time &&
                other.subVer == subVer &&
                other.myAddr == myAddr &&
                other.theirAddr == theirAddr &&
                other.relayTxesBeforeFilter == relayTxesBeforeFilter
    }

    override fun hashCode(): Int {
        return Objects.hashCode(bestHeight, clientVersion, localServices,
                time, subVer, myAddr, theirAddr, relayTxesBeforeFilter)
    }

    override fun toString(): String {
        val stringBuilder = StringBuilder()
        stringBuilder.append("\n")
        stringBuilder.append("client version: ").append(clientVersion).append("\n")
        stringBuilder.append("local services: ").append(localServices).append("\n")
        stringBuilder.append("time:           ").append(time).append("\n")
        stringBuilder.append("my addr:        ").append(myAddr).append("\n")
        stringBuilder.append("their addr:     ").append(theirAddr).append("\n")
        stringBuilder.append("sub version:    ").append(subVer).append("\n")
        stringBuilder.append("best height:    ").append(bestHeight).append("\n")
        stringBuilder.append("delay tx relay: ").append(!relayTxesBeforeFilter).append("\n")
        return stringBuilder.toString()
    }

    fun duplicate(): VersionMessage {
        val v = VersionMessage(params, bestHeight.toInt())
        v.clientVersion = clientVersion
        v.localServices = localServices
        v.time = time
        v.myAddr = myAddr
        v.theirAddr = theirAddr
        v.subVer = subVer
        v.relayTxesBeforeFilter = relayTxesBeforeFilter
        return v
    }

    /**
     * Appends the given user-agent information to the subVer field. The subVer is composed of a series of
     * name:version pairs separated by slashes in the form of a path. For example a typical subVer field for bitcoinj
     * users might look like "/bitcoinj:0.13/MultiBit:1.2/" where libraries come further to the left.
     *
     *
     *
     * There can be as many components as you feel a need for, and the version string can be anything, but it is
     * recommended to use A.B.C where A = major, B = minor and C = revision for software releases, and dates for
     * auto-generated source repository snapshots. A valid subVer begins and ends with a slash, therefore name
     * and version are not allowed to contain such characters.
     *
     *
     *
     * Anything put in the "comments" field will appear in brackets and may be used for platform info, or anything
     * else. For example, calling <tt>appendToSubVer("MultiBit", "1.0", "Windows")</tt> will result in a subVer being
     * set of "/bitcoinj:1.0/MultiBit:1.0(Windows)/". Therefore the / ( and ) characters are reserved in all these
     * components. If you don't want to add a comment (recommended), pass null.
     *
     *
     *
     * See [BIP 14](https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki) for more information.
     *
     * @param comments Optional (can be null) platform or other node specific information.
     * @throws IllegalArgumentException if name, version or comments contains invalid characters.
     */
    fun appendToSubVer(name: String, version: String, comments: String?) {
        checkSubVerComponent(name)
        checkSubVerComponent(version)
        if (comments != null) {
            checkSubVerComponent(comments)
            subVer = subVer + String.format(Locale.US, "%s:%s(%s)/", name, version, comments)
        } else {
            subVer = subVer + String.format(Locale.US, "%s:%s/", name, version)
        }
    }

    companion object {

        /** A service bit that denotes whether the peer has a copy of the block chain or not.  */
        val NODE_NETWORK = 1 shl 0
        /** A service bit that denotes whether the peer supports the getutxos message or not.  */
        val NODE_GETUTXOS = 1 shl 1
        /** A service bit used by Bitcoin-ABC to announce Bitcoin Cash nodes.  */
        val NODE_BITCOIN_CASH = 1 shl 5

        /** The version of this library release, as a string.  */
        val BITCOINJ_VERSION = "0.14.5.2"
        /** The value that is prepended to the subVer field of this application.  */
        val LIBRARY_SUBVER = "/bitcoinj.cash:$BITCOINJ_VERSION/"

        private fun checkSubVerComponent(component: String) {
            if (component.contains("/") || component.contains("(") || component.contains(")"))
                throw IllegalArgumentException("name contains invalid characters")
        }
    }
}
