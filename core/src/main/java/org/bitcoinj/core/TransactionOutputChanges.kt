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

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.LinkedList

/**
 *
 * TransactionOutputChanges represents a delta to the set of unspent outputs. It used as a return value for
 * [AbstractBlockChain.connectTransactions]. It contains the full list of transaction outputs created
 * and spent in a block. It DOES contain outputs created that were spent later in the block, as those are needed for
 * BIP30 (no duplicate txid creation if the previous one was not fully spent prior to this block) verification.
 */
class TransactionOutputChanges {
    val txOutsCreated: MutableList<UTXO>
    val txOutsSpent: MutableList<UTXO>

    constructor(txOutsCreated: MutableList<UTXO>, txOutsSpent: MutableList<UTXO>) {
        this.txOutsCreated = txOutsCreated
        this.txOutsSpent = txOutsSpent
    }

    @Throws(IOException::class)
    constructor(`in`: InputStream) {
        val numOutsCreated = `in`.read() and 0xFF or
                (`in`.read() and 0xFF shl 8) or
                (`in`.read() and 0xFF shl 16) or
                (`in`.read() and 0xFF shl 24)
        txOutsCreated = LinkedList()
        for (i in 0 until numOutsCreated)
            txOutsCreated.add(UTXO(`in`))

        val numOutsSpent = `in`.read() and 0xFF or
                (`in`.read() and 0xFF shl 8) or
                (`in`.read() and 0xFF shl 16) or
                (`in`.read() and 0xFF shl 24)
        txOutsSpent = LinkedList()
        for (i in 0 until numOutsSpent)
            txOutsSpent.add(UTXO(`in`))
    }

    @Throws(IOException::class)
    fun serializeToStream(bos: OutputStream) {
        val numOutsCreated = txOutsCreated.size
        bos.write(0xFF and numOutsCreated)
        bos.write(0xFF and (numOutsCreated shr 8))
        bos.write(0xFF and (numOutsCreated shr 16))
        bos.write(0xFF and (numOutsCreated shr 24))
        for (output in txOutsCreated) {
            output.serializeToStream(bos)
        }

        val numOutsSpent = txOutsSpent.size
        bos.write(0xFF and numOutsSpent)
        bos.write(0xFF and (numOutsSpent shr 8))
        bos.write(0xFF and (numOutsSpent shr 16))
        bos.write(0xFF and (numOutsSpent shr 24))
        for (output in txOutsSpent) {
            output.serializeToStream(bos)
        }
    }
}
