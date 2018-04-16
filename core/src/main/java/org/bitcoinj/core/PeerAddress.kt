/*
 * Copyright 2011 Google Inc.
 * Copyright 2015 Andreas Schildbach
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

import org.bitcoinj.params.MainNetParams
import com.google.common.base.Objects
import com.google.common.net.InetAddresses

import java.io.IOException
import java.io.OutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException

import org.bitcoinj.core.Utils.uint32ToByteStreamLE
import org.bitcoinj.core.Utils.uint64ToByteStreamLE
import com.google.common.base.Preconditions.checkNotNull

/**
 *
 * A PeerAddress holds an IP address and port number representing the network location of
 * a peer in the Bitcoin P2P network. It exists primarily for serialization purposes.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class PeerAddress : ChildMessage {

    private var addr: InetAddress? = null
    var hostname: String? = null
        private set // Used for .onion addresses
    private var port: Int = 0
    private var services: BigInteger? = null
    private var time: Long = 0

    val socketAddress: InetSocketAddress
        get() = InetSocketAddress(getAddr(), getPort())

    /**
     * Construct a peer address from a serialized payload.
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray, offset: Int, protocolVersion: Int) : super(params, payload, offset, protocolVersion) {
    }

    /**
     * Construct a peer address from a serialized payload.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @param serializer the serializer to use for this message.
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters?, payload: ByteArray?, offset: Int, protocolVersion: Int, parent: Message, serializer: MessageSerializer?) : super(params, payload, offset, protocolVersion, parent, serializer, Message.UNKNOWN_LENGTH) {
    }

    /**
     * Construct a peer address from a memorized or hardcoded address.
     */
    @JvmOverloads constructor(addr: InetAddress, port: Int = MainNetParams.get().port, protocolVersion: Int = NetworkParameters.ProtocolVersion.CURRENT.bitcoinProtocolVersion) {
        this.addr = checkNotNull(addr)
        this.port = port
        this.protocolVersion = protocolVersion
        this.services = BigInteger.ZERO
        length = if (protocolVersion > 31402) MESSAGE_SIZE else MESSAGE_SIZE - 4
    }

    /**
     * Constructs a peer address from the given IP address and port.
     */
    @JvmOverloads constructor(params: NetworkParameters, addr: InetAddress, port: Int = params.port) : this(addr, port, params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT)) {}

    /**
     * Constructs a peer address from an [InetSocketAddress]. An InetSocketAddress can take in as parameters an
     * InetAddress or a String hostname. If you want to connect to a .onion, set the hostname to the .onion address.
     * Protocol version is the default.  Protocol version is the default
     * for Bitcoin.
     */
    constructor(addr: InetSocketAddress) : this(addr.address, addr.port, NetworkParameters.ProtocolVersion.CURRENT.bitcoinProtocolVersion) {}

    /**
     * Constructs a peer address from an [InetSocketAddress]. An InetSocketAddress can take in as parameters an
     * InetAddress or a String hostname. If you want to connect to a .onion, set the hostname to the .onion address.
     */
    constructor(params: NetworkParameters, addr: InetSocketAddress) : this(params, addr.address, addr.port) {}

    /**
     * Constructs a peer address from a stringified hostname+port. Use this if you want to connect to a Tor .onion address.
     * Protocol version is the default for Bitcoin.
     */
    constructor(hostname: String, port: Int) {
        this.hostname = hostname
        this.port = port
        this.protocolVersion = NetworkParameters.ProtocolVersion.CURRENT.bitcoinProtocolVersion
        this.services = BigInteger.ZERO
    }

    /**
     * Constructs a peer address from a stringified hostname+port. Use this if you want to connect to a Tor .onion address.
     */
    constructor(params: NetworkParameters, hostname: String, port: Int) : super(params) {
        this.hostname = hostname
        this.port = port
        this.protocolVersion = params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT)
        this.services = BigInteger.ZERO
    }

    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
        if (protocolVersion >= 31402) {
            //TODO this appears to be dynamic because the client only ever sends out it's own address
            //so assumes itself to be up.  For a fuller implementation this needs to be dynamic only if
            //the address refers to this client.
            val secs = Utils.currentTimeSeconds().toInt()
            uint32ToByteStreamLE(secs.toLong(), stream)
        }
        uint64ToByteStreamLE(services!!, stream)  // nServices.
        // Java does not provide any utility to map an IPv4 address into IPv6 space, so we have to do it by hand.
        var ipBytes = addr!!.address
        if (ipBytes.size == 4) {
            val v6addr = ByteArray(16)
            System.arraycopy(ipBytes, 0, v6addr, 12, 4)
            v6addr[10] = 0xFF.toByte()
            v6addr[11] = 0xFF.toByte()
            ipBytes = v6addr
        }
        stream.write(ipBytes)
        // And write out the port. Unlike the rest of the protocol, address and port is in big endian byte order.
        stream.write((0xFF and (port shr 8)).toByte().toInt())
        stream.write((0xFF and port).toByte().toInt())
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        // Format of a serialized address:
        //   uint32 timestamp
        //   uint64 services   (flags determining what the node can do)
        //   16 bytes ip address
        //   2 bytes port num
        if (protocolVersion > 31402)
            time = readUint32()
        else
            time = -1
        services = readUint64()
        val addrBytes = readBytes(16)
        try {
            addr = InetAddress.getByAddress(addrBytes)
        } catch (e: UnknownHostException) {
            throw RuntimeException(e)  // Cannot happen.
        }

        port = 0xFF and payload!![cursor++].toInt() shl 8 or (0xFF and payload!![cursor++].toInt())
        // The 4 byte difference is the uint32 timestamp that was introduced in version 31402
        length = if (protocolVersion > 31402) MESSAGE_SIZE else MESSAGE_SIZE - 4
    }

    fun getAddr(): InetAddress? {
        return addr
    }

    fun setAddr(addr: InetAddress) {
        unCache()
        this.addr = addr
    }

    fun getPort(): Int {
        return port
    }

    fun setPort(port: Int) {
        unCache()
        this.port = port
    }

    fun getServices(): BigInteger? {
        return services
    }

    fun setServices(services: BigInteger) {
        unCache()
        this.services = services
    }

    fun getTime(): Long {
        return time
    }

    fun setTime(time: Long) {
        unCache()
        this.time = time
    }

    override fun toString(): String {
        return if (hostname != null) {
            "[$hostname]:$port"
        } else "[" + addr!!.hostAddress + "]:" + port
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as PeerAddress?
        return other!!.addr == addr && other.port == port && other.time == time && other.services == services
        //TODO: including services and time could cause same peer to be added multiple times in collections
    }

    override fun hashCode(): Int {
        return Objects.hashCode(addr, port, time, services)
    }

    fun toSocketAddress(): InetSocketAddress {
        // Reconstruct the InetSocketAddress properly
        return if (hostname != null) {
            InetSocketAddress.createUnresolved(hostname!!, port)
        } else {
            InetSocketAddress(addr, port)
        }
    }

    companion object {

        internal val MESSAGE_SIZE = 30

        fun localhost(params: NetworkParameters): PeerAddress {
            return PeerAddress(params, InetAddresses.forString("127.0.0.1"), params.port)
        }
    }
}
/**
 * Constructs a peer address from the given IP address and port. Protocol version is the default
 * for Bitcoin.
 */
/**
 * Constructs a peer address from the given IP address. Port and version number
 * are default for Bitcoin mainnet.
 */
/**
 * Constructs a peer address from the given IP address. Port is default for
 * Bitcoin mainnet, version number is default for the given parameters.
 */
