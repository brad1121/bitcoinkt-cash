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

import com.google.common.base.Objects
import org.bitcoinj.script.*
import org.bitcoinj.wallet.*

import javax.annotation.*
import java.io.*

import com.google.common.base.Preconditions.*

/**
 *
 * This message is a reference or pointer to an output of a different transaction.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class TransactionOutPoint : ChildMessage {

    /** Hash of the transaction to which we refer.  */
    /**
     * Returns the hash of the transaction this outpoint references/spends/is connected to.
     */
    override var hash: Sha256Hash? = null
        internal set(value: Sha256Hash?) {
            super.hash = value
        }
    /** Which output of that transaction we are talking about.  */
    var index: Long = 0

    // This is not part of bitcoin serialization. It points to the connected transaction.
    internal var fromTx: Transaction? = null

    // The connected output.
    private val connectedOutput: TransactionOutput?

    /**
     * Returns the pubkey script from the connected output.
     * @throws java.lang.NullPointerException if there is no connected output.
     */
    val connectedPubKeyScript: ByteArray
        get() {
            val result = checkNotNull<TransactionOutput>(getConnectedOutput()).scriptBytes
            checkState(result!!.size > 0)
            return result
        }

    constructor(params: NetworkParameters, index: Long, fromTx: Transaction?) : super(params) {
        this.index = index
        if (fromTx != null) {
            this.hash = fromTx.hash
            this.fromTx = fromTx
        } else {
            // This happens when constructing the genesis block.
            hash = Sha256Hash.ZERO_HASH
        }
        length = MESSAGE_LENGTH
    }

    constructor(params: NetworkParameters, index: Long, hash: Sha256Hash?) : super(params) {
        this.index = index
        this.hash = hash
        length = MESSAGE_LENGTH
    }

    constructor(params: NetworkParameters, connectedOutput: TransactionOutput) : this(params, connectedOutput.index.toLong(), connectedOutput.parentTransactionHash) {
        this.connectedOutput = connectedOutput
    }

/**
 * /**
 * Deserializes the message. This is usually part of a transaction message.
*/
@Throws(ProtocolException::class)
constructor(params:NetworkParameters, payload:ByteArray, offset:Int) : super(params, payload, offset) {}

/**
 * Deserializes the message. This is usually part of a transaction message.
 * @param params NetworkParameters object.
 * @param offset The location of the first payload byte within the array.
 * @param serializer the serializer to use for this message.
 * @throws ProtocolException
*/
@Throws(ProtocolException::class)
constructor(params:NetworkParameters, payload:ByteArray, offset:Int, parent:Message, serializer:MessageSerializer) : super(params, payload, offset, parent, serializer, MESSAGE_LENGTH) {}

@Throws(ProtocolException::class)
protected override fun parse() {
length = MESSAGE_LENGTH
hash = readHash()
index = readUint32()
}

@Throws(IOException::class)
public override fun bitcoinSerializeToStream(stream:OutputStream) {
stream.write(hash!!.reversedBytes)
Utils.uint32ToByteStreamLE(index, stream)
}

/**
 * An outpoint is a part of a transaction input that points to the output of another transaction. If we have both
 * sides in memory, and they have been linked together, this returns a pointer to the connected output, or null
 * if there is no such connection.
*/
fun getConnectedOutput():TransactionOutput? {
if (fromTx != null)
{
return fromTx!!.getOutputs().get(index.toInt())
}
else if (connectedOutput != null)
{
return connectedOutput
}
return null
}

/**
 * Returns the ECKey identified in the connected output, for either pay-to-address scripts or pay-to-key scripts.
 * For P2SH scripts you can use [.getConnectedRedeemData] and then get the
 * key from RedeemData.
 * If the script form cannot be understood, throws ScriptException.
 *
 * @return an ECKey or null if the connected key cannot be found in the wallet.
*/
@Throws(ScriptException::class)
fun getConnectedKey(keyBag:KeyBag):ECKey? {
val connectedOutput = getConnectedOutput()
checkNotNull<TransactionOutput>(connectedOutput, "Input is not connected so cannot retrieve key")
val connectedScript = connectedOutput!!.getScriptPubKey()
if (connectedScript.isSentToAddress())
{
val addressBytes = connectedScript.getPubKeyHash()
return keyBag.findKeyFromPubHash(addressBytes)
}
else if (connectedScript.isSentToRawPubKey())
{
val pubkeyBytes = connectedScript.getPubKey()
return keyBag.findKeyFromPubKey(pubkeyBytes)
}
else
{
throw ScriptException("Could not understand form of connected output script: " + connectedScript)
}
}

/**
 * Returns the RedeemData identified in the connected output, for either pay-to-address scripts, pay-to-key
 * or P2SH scripts.
 * If the script forms cannot be understood, throws ScriptException.
 *
 * @return a RedeemData or null if the connected data cannot be found in the wallet.
*/
@Throws(ScriptException::class)
fun getConnectedRedeemData(keyBag:KeyBag):RedeemData? {
val connectedOutput = getConnectedOutput()
checkNotNull<TransactionOutput>(connectedOutput, "Input is not connected so cannot retrieve key")
val connectedScript = connectedOutput!!.getScriptPubKey()
if (connectedScript.isSentToAddress())
{
val addressBytes = connectedScript.getPubKeyHash()
return RedeemData.of(keyBag.findKeyFromPubHash(addressBytes), connectedScript)
}
else if (connectedScript.isSentToRawPubKey())
{
val pubkeyBytes = connectedScript.getPubKey()
return RedeemData.of(keyBag.findKeyFromPubKey(pubkeyBytes), connectedScript)
}
else if (connectedScript.isPayToScriptHash())
{
val scriptHash = connectedScript.getPubKeyHash()
return keyBag.findRedeemDataFromScriptHash(scriptHash)
}
else
{
throw ScriptException("Could not understand form of connected output script: " + connectedScript)
}
}

public override fun toString():String {
return hash + ":" + index
}

public override fun equals(o:Any?):Boolean {
if (this === o) return true
if (o == null || javaClass != o!!.javaClass) return false
val other = o as TransactionOutPoint?
return index == other!!.index && hash == other!!.hash
}

public override fun hashCode():Int {
return Objects.hashCode(index, hash)
}

companion object {

internal val MESSAGE_LENGTH = 36
}
}
