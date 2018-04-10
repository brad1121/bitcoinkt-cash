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

import org.bitcoinj.store.BlockStore
import org.bitcoinj.store.BlockStoreException
import org.bitcoinj.store.FullPrunedBlockStore
import com.google.common.base.Charsets
import com.google.common.hash.HashCode
import com.google.common.hash.Hasher
import com.google.common.hash.Hashing
import com.google.common.io.BaseEncoding

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.annotation.*
import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.Arrays
import java.util.TreeMap

import com.google.common.base.Preconditions.*

/**
 *
 * Vends hard-coded [StoredBlock]s for blocks throughout the chain. Checkpoints serve two purposes:
 *
 *  1. They act as a safety mechanism against huge re-orgs that could rewrite large chunks of history, thus
 * constraining the block chain to be a consensus mechanism only for recent parts of the timeline.
 *  1. They allow synchronization to the head of the chain for new wallets/users much faster than syncing all
 * headers from the genesis block.
 *
 *
 *
 * Checkpoints are used by the SPV [BlockChain] to initialize fresh
 * [org.bitcoinj.store.SPVBlockStore]s. They are not used by fully validating mode, which instead has a
 * different concept of checkpoints that are used to hard-code the validity of blocks that violate BIP30 (duplicate
 * coinbase transactions). Those "checkpoints" can be found in NetworkParameters.
 *
 *
 * The file format consists of the string "CHECKPOINTS 1", followed by a uint32 containing the number of signatures
 * to read. The value may not be larger than 256 (so it could have been a byte but isn't for historical reasons).
 * If the number of signatures is larger than zero, each 65 byte ECDSA secp256k1 signature then follows. The signatures
 * sign the hash of all bytes that follow the last signature.
 *
 *
 * After the signatures come an int32 containing the number of checkpoints in the file. Then each checkpoint follows
 * one after the other. A checkpoint is 12 bytes for the total work done field, 4 bytes for the height, 80 bytes
 * for the block header and then 1 zero byte at the end (i.e. number of transactions in the block: always zero).
 */
class CheckpointManager
/** Loads the checkpoints from the given stream  */
@Throws(IOException::class)
constructor(params: NetworkParameters, inputStream: InputStream?) {

    // Map of block header time to data.
    protected val checkpoints = TreeMap<Long, StoredBlock>()

    protected val params: NetworkParameters
    /** Returns a hash of the concatenated checkpoint data.  */
    val dataHash: Sha256Hash

    /** Loads the default checkpoints bundled with bitcoinj  */
    @Throws(IOException::class)
    constructor(context: Context) : this(context.params, null) {
    }

    init {
        var inputStream = inputStream
        this.params = checkNotNull(params)
        if (inputStream == null)
            inputStream = openStream(params)
        checkNotNull(inputStream)
        inputStream = BufferedInputStream(inputStream)
        inputStream.mark(1)
        val first = inputStream.read()
        inputStream.reset()
        if (first == BINARY_MAGIC[0].toInt())
            dataHash = readBinary(inputStream)
        else if (first == TEXTUAL_MAGIC[0].toInt())
            dataHash = readTextual(inputStream)
        else
            throw IOException("Unsupported format.")
    }

    @Throws(IOException::class)
    private fun readBinary(inputStream: InputStream): Sha256Hash {
        var dis: DataInputStream? = null
        try {
            val digest = Sha256Hash.newDigest()
            val digestInputStream = DigestInputStream(inputStream, digest)
            dis = DataInputStream(digestInputStream)
            digestInputStream.on(false)
            val header = ByteArray(BINARY_MAGIC.length)
            dis.readFully(header)
            if (!Arrays.equals(header, BINARY_MAGIC.toByteArray(charset("US-ASCII"))))
                throw IOException("Header bytes did not match expected version")
            val numSignatures = checkPositionIndex(dis.readInt(), MAX_SIGNATURES, "Num signatures out of range")
            for (i in 0 until numSignatures) {
                val sig = ByteArray(65)
                dis.readFully(sig)
                // TODO: Do something with the signature here.
            }
            digestInputStream.on(true)
            val numCheckpoints = dis.readInt()
            checkState(numCheckpoints > 0)
            val size = StoredBlock.COMPACT_SERIALIZED_SIZE
            val buffer = ByteBuffer.allocate(size)
            for (i in 0 until numCheckpoints) {
                if (dis.read(buffer.array(), 0, size) < size)
                    throw IOException("Incomplete read whilst loading checkpoints.")
                val block = StoredBlock.deserializeCompact(params, buffer)
                buffer.position(0)
                checkpoints.put(block.header.timeSeconds, block)
            }
            val dataHash = Sha256Hash.wrap(digest.digest())
            log.info("Read {} checkpoints, hash is {}", checkpoints.size, dataHash)
            return dataHash
        } catch (e: ProtocolException) {
            throw IOException(e)
        } finally {
            if (dis != null) dis.close()
            inputStream.close()
        }
    }

    @Throws(IOException::class)
    private fun readTextual(inputStream: InputStream): Sha256Hash {
        val hasher = Hashing.sha256().newHasher()
        var reader: BufferedReader? = null
        try {
            reader = BufferedReader(InputStreamReader(inputStream, Charsets.US_ASCII))
            val magic = reader.readLine()
            if (TEXTUAL_MAGIC != magic)
                throw IOException("unexpected magic: " + magic)
            val numSigs = Integer.parseInt(reader.readLine())
            for (i in 0 until numSigs)
                reader.readLine() // Skip sigs for now.
            val numCheckpoints = Integer.parseInt(reader.readLine())
            checkState(numCheckpoints > 0)
            // Hash numCheckpoints in a way compatible to the binary format.
            hasher.putBytes(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(numCheckpoints).array())
            val size = StoredBlock.COMPACT_SERIALIZED_SIZE
            val buffer = ByteBuffer.allocate(size)
            for (i in 0 until numCheckpoints) {
                val bytes = BASE64.decode(reader.readLine())
                hasher.putBytes(bytes)
                buffer.position(0)
                buffer.put(bytes)
                buffer.position(0)
                val block = StoredBlock.deserializeCompact(params, buffer)
                checkpoints.put(block.header.timeSeconds, block)
            }
            val hash = hasher.hash()
            log.info("Read {} checkpoints, hash is {}", checkpoints.size, hash)
            return Sha256Hash.wrap(hash.asBytes())
        } finally {
            if (reader != null) reader.close()
        }
    }

    /**
     * Returns a [StoredBlock] representing the last checkpoint before the given time, for example, normally
     * you would want to know the checkpoint before the earliest wallet birthday.
     */
    fun getCheckpointBefore(time: Long): StoredBlock {
        try {
            checkArgument(time > params.genesisBlock.timeSeconds)
            // This is thread safe because the map never changes after creation.
            val entry = checkpoints.floorEntry(time)
            if (entry != null) return entry.value
            val genesis = params.genesisBlock.cloneAsHeader()
            return StoredBlock(genesis, genesis.work, 0)
        } catch (e: VerificationException) {
            throw RuntimeException(e)  // Cannot happen.
        }

    }

    /** Returns the number of checkpoints that were loaded.  */
    fun numCheckpoints(): Int {
        return checkpoints.size
    }

    companion object {
        private val log = LoggerFactory.getLogger(CheckpointManager::class.java!!)

        private val BINARY_MAGIC = "CHECKPOINTS 1"
        private val TEXTUAL_MAGIC = "TXT CHECKPOINTS 1"
        private val MAX_SIGNATURES = 256

        val BASE64 = BaseEncoding.base64().omitPadding()

        /** Returns a checkpoints stream pointing to inside the bitcoinj JAR  */
        fun openStream(params: NetworkParameters): InputStream {
            return CheckpointManager::class.java!!.getResourceAsStream("/" + params.id + ".checkpoints.txt")
        }

        /**
         *
         * Convenience method that creates a CheckpointManager, loads the given data, gets the checkpoint for the given
         * time, then inserts it into the store and sets that to be the chain head. Useful when you have just created
         * a new store from scratch and want to use configure it all in one go.
         *
         *
         * Note that time is adjusted backwards by a week to account for possible clock drift in the block headers.
         */
        @Throws(IOException::class, BlockStoreException::class)
        fun checkpoint(params: NetworkParameters, checkpoints: InputStream, store: BlockStore, time: Long) {
            var time = time
            checkNotNull(params)
            checkNotNull(store)
            checkArgument(store !is FullPrunedBlockStore, "You cannot use checkpointing with a full store.")

            time -= (86400 * 7).toLong()

            checkArgument(time > 0)
            log.info("Attempting to initialize a new block store with a checkpoint for time {} ({})", time, Utils.dateTimeFormat(time * 1000))

            val stream = BufferedInputStream(checkpoints)
            val manager = CheckpointManager(params, stream)
            val checkpoint = manager.getCheckpointBefore(time)
            store.put(checkpoint)
            store.chainHead = checkpoint
        }
    }
}
