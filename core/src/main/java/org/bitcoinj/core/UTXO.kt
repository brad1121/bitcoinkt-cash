/*
 * Copyright 2012 Matt Corallo.
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

import org.bitcoinj.script.*
import com.google.common.base.Objects

import java.io.*
import java.math.*
import java.util.Locale

// TODO: Fix this class: should not talk about addresses, height should be optional/support mempool height etc

/**
 * A UTXO message contains the information necessary to check a spending transaction.
 * It avoids having to store the entire parentTransaction just to get the hash and index.
 * Useful when working with free standing outputs.
 */
class UTXO {

    /** The value which this Transaction output holds.  */
    var value: Coin? = null
        private set
    /** The Script object which you can use to get address, script bytes or script type.  */
    var script: Script? = null
        private set
    /** The hash of the transaction which holds this output.  */
    var hash: Sha256Hash? = null
        private set
    /** The index of this output in the transaction which holds it.  */
    var index: Long = 0
        private set
    /** Gets the height of the block that created this output.  */
    var height: Int = 0
        private set
    /** Gets the flag of whether this was created by a coinbase tx.  */
    var isCoinbase: Boolean = false
        private set
    /** The address of this output, can be the empty string if none was provided at construction time or was deserialized  */
    var address: String? = null
        private set

    /**
     * Creates a stored transaction output.
     *
     * @param hash     The hash of the containing transaction.
     * @param index    The outpoint.
     * @param value    The value available.
     * @param height   The height this output was created in.
     * @param coinbase The coinbase flag.
     */
    constructor(hash: Sha256Hash,
                index: Long,
                value: Coin,
                height: Int,
                coinbase: Boolean,
                script: Script) {
        this.hash = hash
        this.index = index
        this.value = value
        this.height = height
        this.script = script
        this.isCoinbase = coinbase
        this.address = ""
    }

    /**
     * Creates a stored transaction output.
     *
     * @param hash     The hash of the containing transaction.
     * @param index    The outpoint.
     * @param value    The value available.
     * @param height   The height this output was created in.
     * @param coinbase The coinbase flag.
     * @param address  The address.
     */
    constructor(hash: Sha256Hash,
                index: Long,
                value: Coin,
                height: Int,
                coinbase: Boolean,
                script: Script,
                address: String) : this(hash, index, value, height, coinbase, script) {
        this.address = address
    }

    @Throws(IOException::class)
    constructor(`in`: InputStream) {
        val valueBytes = ByteArray(8)
        if (`in`.read(valueBytes, 0, 8) != 8)
            throw EOFException()
        value = Coin.valueOf(Utils.readInt64(valueBytes, 0))

        val scriptBytesLength = `in`.read() and 0xFF or
                (`in`.read() and 0xFF shl 8) or
                (`in`.read() and 0xFF shl 16) or
                (`in`.read() and 0xFF shl 24)
        val scriptBytes = ByteArray(scriptBytesLength)
        if (`in`.read(scriptBytes) != scriptBytesLength)
            throw EOFException()
        script = Script(scriptBytes)

        val hashBytes = ByteArray(32)
        if (`in`.read(hashBytes) != 32)
            throw EOFException()
        hash = Sha256Hash.wrap(hashBytes)

        val indexBytes = ByteArray(4)
        if (`in`.read(indexBytes) != 4)
            throw EOFException()
        index = Utils.readUint32(indexBytes, 0)

        height = `in`.read() and 0xFF or
                (`in`.read() and 0xFF shl 8) or
                (`in`.read() and 0xFF shl 16) or
                (`in`.read() and 0xFF shl 24)

        val coinbaseByte = ByteArray(1)
        `in`.read(coinbaseByte)
        isCoinbase = coinbaseByte[0].toInt() == 1
    }

    override fun toString(): String {
        return String.format(Locale.US, "Stored TxOut of %s (%s:%d)", value!!.toFriendlyString(), hash, index)
    }

    override fun hashCode(): Int {
        return Objects.hashCode(index, hash)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as UTXO?
        return index == other!!.index && hash == other.hash
    }

    @Throws(IOException::class)
    fun serializeToStream(bos: OutputStream) {
        Utils.uint64ToByteStreamLE(BigInteger.valueOf(value!!.value), bos)

        val scriptBytes = script!!.program
        bos.write(0xFF and scriptBytes.size)
        bos.write(0xFF and (scriptBytes.size shr 8))
        bos.write(0xFF and (scriptBytes.size shr 16))
        bos.write(0xFF and (scriptBytes.size shr 24))
        bos.write(scriptBytes)

        bos.write(hash!!.bytes)
        Utils.uint32ToByteStreamLE(index, bos)

        bos.write(0xFF and height)
        bos.write(0xFF and (height shr 8))
        bos.write(0xFF and (height shr 16))
        bos.write(0xFF and (height shr 24))

        bos.write(byteArrayOf((if (isCoinbase) 1 else 0).toByte()))
    }
}
