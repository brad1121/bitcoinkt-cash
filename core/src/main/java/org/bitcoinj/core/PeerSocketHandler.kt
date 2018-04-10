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

import org.bitcoinj.net.AbstractTimeoutHandler
import org.bitcoinj.net.MessageWriteTarget
import org.bitcoinj.net.StreamConnection
import org.bitcoinj.utils.Threading
import com.google.common.annotations.VisibleForTesting
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.channels.NotYetConnectedException
import java.util.concurrent.locks.Lock

import com.google.common.base.Preconditions.*

/**
 * Handles high-level message (de)serialization for peers, acting as the bridge between the
 * [org.bitcoinj.net] classes and [Peer].
 */
abstract class PeerSocketHandler : AbstractTimeoutHandler, StreamConnection {

    private val serializer: MessageSerializer
    /**
     * @return the IP address and port of peer.
     */
    var address: PeerAddress? = null
        protected set
    // If we close() before we know our writeTarget, set this to true to call writeTarget.closeConnection() right away.
    private var closePending = false
    // writeTarget will be thread-safe, and may call into PeerGroup, which calls us, so we should call it unlocked
    @VisibleForTesting
    var writeTarget: MessageWriteTarget? = null

    // The ByteBuffers passed to us from the writeTarget are static in size, and usually smaller than some messages we
    // will receive. For SPV clients, this should be rare (ie we're mostly dealing with small transactions), but for
    // messages which are larger than the read buffer, we have to keep a temporary buffer with its bytes.
    private var largeReadBuffer: ByteArray? = null
    private var largeReadBufferPos: Int = 0
    private var header: BitcoinSerializer.BitcoinPacketHeader? = null

    private val lock = Threading.lock("PeerSocketHandler")

    constructor(params: NetworkParameters, remoteIp: InetSocketAddress) {
        checkNotNull(params)
        serializer = params.getDefaultSerializer()
        this.address = PeerAddress(params, remoteIp)
    }

    constructor(params: NetworkParameters, peerAddress: PeerAddress) {
        checkNotNull(params)
        serializer = params.getDefaultSerializer()
        this.address = checkNotNull(peerAddress)
    }

    /**
     * Sends the given message to the peer. Due to the asynchronousness of network programming, there is no guarantee
     * the peer will have received it. Throws NotYetConnectedException if we are not yet connected to the remote peer.
     * TODO: Maybe use something other than the unchecked NotYetConnectedException here
     */
    @Throws(NotYetConnectedException::class)
    fun sendMessage(message: Message) {
        lock.lock()
        try {
            if (writeTarget == null)
                throw NotYetConnectedException()
        } finally {
            lock.unlock()
        }
        // TODO: Some round-tripping could be avoided here
        val out = ByteArrayOutputStream()
        try {
            serializer.serialize(message, out)
            writeTarget!!.writeBytes(out.toByteArray())
        } catch (e: IOException) {
            exceptionCaught(e)
        }

    }

    /**
     * Closes the connection to the peer if one exists, or immediately closes the connection as soon as it opens
     */
    fun close() {
        lock.lock()
        try {
            if (writeTarget == null) {
                closePending = true
                return
            }
        } finally {
            lock.unlock()
        }
        writeTarget!!.closeConnection()
    }

    override fun timeoutOccurred() {
        log.info("{}: Timed out", address)
        close()
    }

    /**
     * Called every time a message is received from the network
     */
    @Throws(Exception::class)
    protected abstract fun processMessage(m: Message)

    override fun receiveBytes(buff: ByteBuffer): Int {
        checkArgument(buff.position() == 0 && buff.capacity() >= BitcoinSerializer.BitcoinPacketHeader.HEADER_LENGTH + 4)
        try {
            // Repeatedly try to deserialize messages until we hit a BufferUnderflowException
            var firstMessage = true
            while (true) {
                // If we are in the middle of reading a message, try to fill that one first, before we expect another
                if (largeReadBuffer != null) {
                    // This can only happen in the first iteration
                    checkState(firstMessage)
                    // Read new bytes into the largeReadBuffer
                    val bytesToGet = Math.min(buff.remaining(), largeReadBuffer!!.size - largeReadBufferPos)
                    buff.get(largeReadBuffer!!, largeReadBufferPos, bytesToGet)
                    largeReadBufferPos += bytesToGet
                    // Check the largeReadBuffer's status
                    if (largeReadBufferPos == largeReadBuffer!!.size) {
                        // ...processing a message if one is available
                        processMessage(serializer.deserializePayload(header, ByteBuffer.wrap(largeReadBuffer!!)))
                        largeReadBuffer = null
                        header = null
                        firstMessage = false
                    } else
                    // ...or just returning if we don't have enough bytes yet
                        return buff.position()
                }
                // Now try to deserialize any messages left in buff
                val message: Message
                val preSerializePosition = buff.position()
                try {
                    message = serializer.deserialize(buff)
                } catch (e: BufferUnderflowException) {
                    // If we went through the whole buffer without a full message, we need to use the largeReadBuffer
                    if (firstMessage && buff.limit() == buff.capacity()) {
                        // ...so reposition the buffer to 0 and read the next message header
                        buff.position(0)
                        try {
                            serializer.seekPastMagicBytes(buff)
                            header = serializer.deserializeHeader(buff)
                            // Initialize the largeReadBuffer with the next message's size and fill it with any bytes
                            // left in buff
                            largeReadBuffer = ByteArray(header!!.size)
                            largeReadBufferPos = buff.remaining()
                            buff.get(largeReadBuffer!!, 0, largeReadBufferPos)
                        } catch (e1: BufferUnderflowException) {
                            // If we went through a whole buffer's worth of bytes without getting a header, give up
                            // In cases where the buff is just really small, we could create a second largeReadBuffer
                            // that we use to deserialize the magic+header, but that is rather complicated when the buff
                            // should probably be at least that big anyway (for efficiency)
                            throw ProtocolException("No magic bytes+header after reading " + buff.capacity() + " bytes")
                        }

                    } else {
                        // Reposition the buffer to its original position, which saves us from skipping messages by
                        // seeking past part of the magic bytes before all of them are in the buffer
                        buff.position(preSerializePosition)
                    }
                    return buff.position()
                }

                // Process our freshly deserialized message
                processMessage(message)
                firstMessage = false
            }
        } catch (e: Exception) {
            exceptionCaught(e)
            return -1 // Returning -1 also throws an IllegalStateException upstream and kills the connection
        }

    }

    /**
     * Sets the [MessageWriteTarget] used to write messages to the peer. This should almost never be called, it is
     * called automatically by [org.bitcoinj.net.NioClient] or
     * [org.bitcoinj.net.NioClientManager] once the socket finishes initialization.
     */
    override fun setWriteTarget(writeTarget: MessageWriteTarget?) {
        checkArgument(writeTarget != null)
        lock.lock()
        var closeNow = false
        try {
            checkArgument(this.writeTarget == null)
            closeNow = closePending
            this.writeTarget = writeTarget
        } finally {
            lock.unlock()
        }
        if (closeNow)
            writeTarget!!.closeConnection()
    }

    override fun getMaxMessageSize(): Int {
        return Message.MAX_SIZE
    }

    /** Catch any exceptions, logging them and then closing the channel.  */
    private fun exceptionCaught(e: Exception) {
        val addr = address
        val s = addr?.toString() ?: "?"
        if (e is ConnectException || e is IOException) {
            // Short message for network errors
            log.info(s + " - " + e.message)
        } else {
            log.warn(s + " - ", e)
            val handler = Threading.uncaughtExceptionHandler
            handler?.uncaughtException(Thread.currentThread(), e)
        }

        close()
    }

    companion object {
        private val log = LoggerFactory.getLogger(PeerSocketHandler::class.java!!)
    }
}
