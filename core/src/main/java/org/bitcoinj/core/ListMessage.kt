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

import java.io.IOException
import java.io.OutputStream
import java.util.ArrayList
import java.util.Collections

/**
 *
 * Abstract superclass of classes with list based payload, ie InventoryMessage and GetDataMessage.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
abstract class ListMessage : Message {

    private var arrayLen: Long = 0
    // For some reason the compiler complains if this is inside InventoryItem
    var items: MutableList<InventoryItem>? = null
         get(): MutableList<InventoryItem>? {
            return Collections.unmodifiableList(items)
        }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, bytes: ByteArray) : super(params, bytes, 0) {
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray, serializer: MessageSerializer, length: Int) : super(params, payload, 0, serializer, length) {
    }

    constructor(params: NetworkParameters) : super(params) {
        items = ArrayList()
        length = 1 //length of 0 varint;
    }



    fun addItem(item: InventoryItem) {
        unCache()
        length -= VarInt.sizeOf(items!!.size.toLong())
        items!!.add(item)
        length += VarInt.sizeOf(items!!.size.toLong()) + InventoryItem.MESSAGE_LENGTH
    }

    fun removeItem(index: Int) {
        unCache()
        length -= VarInt.sizeOf(items!!.size.toLong())
        items!!.removeAt(index)
        length += VarInt.sizeOf(items!!.size.toLong()) - InventoryItem.MESSAGE_LENGTH
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        arrayLen = readVarInt()
        if (arrayLen > MAX_INVENTORY_ITEMS)
            throw ProtocolException("Too many items in INV message: " + arrayLen)
        length = (cursor - offset + arrayLen * InventoryItem.MESSAGE_LENGTH).toInt()

        // An inv is vector<CInv> where CInv is int+hash. The int is either 1 or 2 for tx or block.
        items = ArrayList(arrayLen.toInt())
        for (i in 0 until arrayLen) {
            if (cursor + InventoryItem.MESSAGE_LENGTH > payload!!.size) {
                throw ProtocolException("Ran off the end of the INV")
            }
            val typeCode = readUint32().toInt()
            val type: InventoryItem.Type
            // See ppszTypeName in net.h
            when (typeCode) {
                0 -> type = InventoryItem.Type.Error
                1 -> type = InventoryItem.Type.Transaction
                2 -> type = InventoryItem.Type.Block
                3 -> type = InventoryItem.Type.FilteredBlock
                else -> throw ProtocolException("Unknown CInv type: " + typeCode)
            }
            val item = InventoryItem(type, readHash())
            items!!.add(item)
        }
        payload = null
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(stream: OutputStream) {
        stream.write(VarInt(items!!.size.toLong()).encode())
        for (i in items!!) {
            // Write out the type code.
            Utils.uint32ToByteStreamLE(i.type.ordinal.toLong(), stream)
            // And now the hash.
            stream.write(i.hash.reversedBytes)
        }
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        return if (o == null || javaClass != o.javaClass) false else items == (o as ListMessage).items
    }

    override fun hashCode(): Int {
        return items!!.hashCode()
    }

    companion object {

        val MAX_INVENTORY_ITEMS: Long = 50000
    }
}
