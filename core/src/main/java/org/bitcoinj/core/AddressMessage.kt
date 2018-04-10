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

import org.bitcoinj.core.Utils.join
import java.io.IOException
import java.io.OutputStream
import java.util.ArrayList
import java.util.Collections

/**
 *
 * Represents an "addr" message on the P2P network, which contains broadcast IP addresses of other peers. This is
 * one of the ways peers can find each other without using the DNS or IRC discovery mechanisms. However storing and
 * using addr messages is not presently implemented.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class AddressMessage : Message {
    private var addresses: MutableList<PeerAddress>? = null

    /**
     * Contruct a new 'addr' message.
     * @param params NetworkParameters object.
     * @param offset The location of the first payload byte within the array.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.
     * If true and the backing byte array is invalidated due to modification of a field then
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    internal constructor(params: NetworkParameters, payload: ByteArray, offset: Int, setSerializer: MessageSerializer, length: Int) : super(params, payload, offset, setSerializer, length) {
    }

    /**
     * Contruct a new 'addr' message.
     * @param params NetworkParameters object.
     * @param serializer the serializer to use for this block.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    internal constructor(params: NetworkParameters, payload: ByteArray, serializer: MessageSerializer, length: Int) : super(params, payload, 0, serializer, length) {
    }

    @Throws(ProtocolException::class)
    internal constructor(params: NetworkParameters, payload: ByteArray, offset: Int) : super(params, payload, offset, params.defaultSerializer, Message.UNKNOWN_LENGTH) {
    }

    @Throws(ProtocolException::class)
    internal constructor(params: NetworkParameters, payload: ByteArray) : super(params, payload, 0, params.defaultSerializer, Message.UNKNOWN_LENGTH) {
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        val numAddresses = readVarInt()
        // Guard against ultra large messages that will crash us.
        if (numAddresses > MAX_ADDRESSES)
            throw ProtocolException("Address message too large.")
        addresses = ArrayList(numAddresses.toInt())
        for (i in 0 until numAddresses) {
            val addr = PeerAddress(params, payload, cursor, protocolVersion, this, serializer)
            addresses!!.add(addr)
            cursor += addr.messageSize
        }
        length = VarInt(addresses!!.size.toLong()).sizeInBytes
        // The 4 byte difference is the uint32 timestamp that was introduced in version 31402
        length += addresses!!.size * if (protocolVersion > 31402) PeerAddress.MESSAGE_SIZE else PeerAddress.MESSAGE_SIZE - 4
    }

    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
        if (addresses == null)
            return
        stream.write(VarInt(addresses!!.size.toLong()).encode())
        for (addr in addresses!!) {
            addr.bitcoinSerialize(stream)
        }
    }

    /**
     * @return An unmodifiableList view of the backing List of addresses.  Addresses contained within the list may be safely modified.
     */
    fun getAddresses(): List<PeerAddress> {
        return Collections.unmodifiableList(addresses!!)
    }

    fun addAddress(address: PeerAddress) {
        unCache()
        address.parent = this
        addresses!!.add(address)
        if (length == Message.UNKNOWN_LENGTH)
            messageSize
        else
            length += address.messageSize
    }

    fun removeAddress(index: Int) {
        unCache()
        val address = addresses!!.removeAt(index)
        address.parent = null
        if (length == Message.UNKNOWN_LENGTH)
            messageSize
        else
            length -= address.messageSize
    }

    override fun toString(): String {
        return "addr: " + Utils.join(this!!.addresses!!)
    }

    companion object {

        private val MAX_ADDRESSES: Long = 1024
    }
}
