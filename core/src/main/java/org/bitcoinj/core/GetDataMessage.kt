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

/**
 *
 * Represents the "getdata" P2P network message, which requests the contents of blocks or transactions given their
 * hashes.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class GetDataMessage : ListMessage {

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payloadBytes: ByteArray) : super(params, payloadBytes) {
    }

    /**
     * Deserializes a 'getdata' message.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray, serializer: MessageSerializer, length: Int) : super(params, payload, serializer, length) {
    }

    constructor(params: NetworkParameters) : super(params) {}

    fun addTransaction(hash: Sha256Hash) {
        addItem(InventoryItem(InventoryItem.Type.Transaction, hash))
    }

    fun addBlock(hash: Sha256Hash) {
        addItem(InventoryItem(InventoryItem.Type.Block, hash))
    }

    fun addFilteredBlock(hash: Sha256Hash) {
        addItem(InventoryItem(InventoryItem.Type.FilteredBlock, hash))
    }

    fun getHashOf(i: Int): Sha256Hash {
        return getItems()[i].hash
    }
}
