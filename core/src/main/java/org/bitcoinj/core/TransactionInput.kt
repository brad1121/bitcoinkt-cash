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

import org.bitcoinj.script.Script
import org.bitcoinj.wallet.DefaultRiskAnalysis
import org.bitcoinj.wallet.KeyBag
import org.bitcoinj.wallet.RedeemData

import com.google.common.base.Joiner
import com.google.common.base.Objects
import java.io.IOException
import java.io.OutputStream
import java.lang.ref.WeakReference
import java.util.Arrays

import com.google.common.base.Preconditions.checkElementIndex
import com.google.common.base.Preconditions.checkNotNull

/**
 *
 * A transfer of coins from one address to another creates a transaction in which the outputs
 * can be claimed by the recipient in the input of another transaction. You can imagine a
 * transaction as being a module which is wired up to others, the inputs of one have to be wired
 * to the outputs of another. The exceptions are coinbase transactions, which create new coins.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
open class TransactionInput : ChildMessage {

    // Allows for altering transactions after they were broadcast. Values below NO_SEQUENCE-1 mean it can be altered.
    private var sequence: Long = 0
    // Data needed to connect to the output of the transaction we're gathering coins from.
    /**
     * @return The previous output transaction reference, as an OutPoint structure.  This contains the
     * data needed to connect to the output of the transaction we're gathering coins from.
     */
    var outpoint: TransactionOutPoint? = null
        private set
    // The "script bytes" might not actually be a script. In coinbase transactions where new coins are minted there
    // is no input transaction, so instead the scriptBytes contains some extra stuff (like a rollover nonce) that we
    // don't care about much. The bytes are turned into a Script object (cached below) on demand via a getter.
    private var scriptBytes: ByteArray? = null
    // The Script object obtained from parsing scriptBytes. Only filled in on demand and if the transaction is not
    // coinbase.
    private var scriptSig: WeakReference<Script>? = null
    /** Value of the output connected to the input, if known. This field does not participate in equals()/hashCode().  */
    /**
     * @return Value of the output connected to this input, if known. Null if unknown.
     */
    var value: Coin? = null
        private set

    /**
     * Coinbase transactions have special inputs with hashes of zero. If this is such an input, returns true.
     */
    // -1 but all is serialized to the wire as unsigned int.
    val isCoinBase: Boolean
        get() = outpoint!!.hash == Sha256Hash.ZERO_HASH && outpoint!!.index and 0xFFFFFFFFL == 0xFFFFFFFFL

    /**
     * Convenience method that returns the from address of this input by parsing the scriptSig. The concept of a
     * "from address" is not well defined in Bitcoin and you should not assume that senders of a transaction can
     * actually receive coins on the same address they used to sign (e.g. this is not true for shared wallets).
     */
    val fromAddress: Address
        @Deprecated("")
        @Throws(ScriptException::class)
        get() {
            if (isCoinBase) {
                throw ScriptException(
                        "This is a coinbase transaction which generates new coins. It does not have a from address.")
            }
            return getScriptSig().getFromAddress(params)
        }

    /**
     * Sequence numbers allow participants in a multi-party transaction signing protocol to create new versions of the
     * transaction independently of each other. Newer versions of a transaction can replace an existing version that's
     * in nodes memory pools if the existing version is time locked. See the Contracts page on the Bitcoin wiki for
     * examples of how you can use this feature to build contract protocols.
     */
    /**
     * Sequence numbers allow participants in a multi-party transaction signing protocol to create new versions of the
     * transaction independently of each other. Newer versions of a transaction can replace an existing version that's
     * in nodes memory pools if the existing version is time locked. See the Contracts page on the Bitcoin wiki for
     * examples of how you can use this feature to build contract protocols.
     */
    var sequenceNumber: Long
        get() = sequence
        set(sequence) {
            unCache()
            this.sequence = sequence
        }

    /**
     * @return The Transaction that owns this input.
     */
    val parentTransaction: Transaction
        get() = parent as Transaction

    /**
     * Returns whether this input will cause a transaction to opt into the
     * [full replace-by-fee ](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki) semantics.
     */
    val isOptInFullRBF: Boolean
        get() = sequence < NO_SEQUENCE - 1

    /**
     * Returns the connected output, assuming the input was connected with
     * [TransactionInput.connect] or variants at some point. If it wasn't connected, then
     * this method returns null.
     */
    val connectedOutput: TransactionOutput?
        get() = outpoint!!.getConnectedOutput()

    /**
     * Returns the connected transaction, assuming the input was connected with
     * [TransactionInput.connect] or variants at some point. If it wasn't connected, then
     * this method returns null.
     */
    val connectedTransaction: Transaction?
        get() = outpoint!!.fromTx

    /**
     *
     * Returns either RuleViolation.NONE if the input is standard, or which rule makes it non-standard if so.
     * The "IsStandard" rules control whether the default Bitcoin Core client blocks relay of a tx / refuses to mine it,
     * however, non-standard transactions can still be included in blocks and will be accepted as valid if so.
     *
     *
     * This method simply calls <tt>DefaultRiskAnalysis.isInputStandard(this)</tt>.
     */
    val isStandard: DefaultRiskAnalysis.RuleViolation
        get() = DefaultRiskAnalysis.isInputStandard(this)

    @JvmOverloads constructor(params: NetworkParameters, parentTransaction: Transaction?, scriptBytes: ByteArray?,
                              outpoint: TransactionOutPoint = TransactionOutPoint(params, UNCONNECTED, null as Transaction?), value: Coin? = null) : super(params) {
        this.scriptBytes = scriptBytes
        this.outpoint = outpoint
        this.sequence = NO_SEQUENCE
        this.value = value
        parent = (parentTransaction)
        length = 40 + if (scriptBytes == null) 1 else VarInt.sizeOf(scriptBytes.size.toLong()) + scriptBytes.size
    }

    /**
     * Creates an UNSIGNED input that links to the given output
     */
    internal constructor(params: NetworkParameters, parentTransaction: Transaction, output: TransactionOutput) : super(params) {
        val outputIndex = output.index.toLong()
        if (output.parentTransaction != null) {
            outpoint = TransactionOutPoint(params, outputIndex, output.parentTransaction)
        } else {
            outpoint = TransactionOutPoint(params, output)
        }
        scriptBytes = EMPTY_ARRAY
        sequence = NO_SEQUENCE
        parent = (parentTransaction)
        this.value = output.getValue()
        length = 41
    }

    /**
     * Deserializes an input message. This is usually part of a transaction message.
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, parentTransaction: Transaction?, payload: ByteArray, offset: Int) : super(params, payload, offset) {
        parent = (parentTransaction)
        this.value = null
    }

    /**
     * Deserializes an input message. This is usually part of a transaction message.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @throws ProtocolException
     */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, parentTransaction: Transaction, payload: ByteArray, offset: Int, serializer: MessageSerializer) : super(params, payload, offset, parentTransaction, serializer, Message.UNKNOWN_LENGTH) {
        this.value = null
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        outpoint = TransactionOutPoint(params!!, payload!!, cursor, this, serializer!!)
        cursor += outpoint!!.messageSize
        val scriptLen = readVarInt().toInt()
        length = cursor - offset + scriptLen + 4
        scriptBytes = readBytes(scriptLen)
        sequence = readUint32()
    }

    @Throws(IOException::class)
    override fun bitcoinSerializeToStream(stream: OutputStream) {
        outpoint!!.bitcoinSerialize(stream)
        stream.write(VarInt(scriptBytes!!.size.toLong()).encode())
        stream.write(scriptBytes!!)
        Utils.uint32ToByteStreamLE(sequence, stream)
    }

    /**
     * Returns the script that is fed to the referenced output (scriptPubKey) script in order to satisfy it: usually
     * contains signatures and maybe keys, but can contain arbitrary data if the output script accepts it.
     */
    @Throws(ScriptException::class)
    open fun getScriptSig(): Script {
        // Transactions that generate new coins don't actually have a script. Instead this
        // parameter is overloaded to be something totally different.
        var script: Script? = if (scriptSig == null) null else scriptSig!!.get()
        if (script == null) {
            script = Script(scriptBytes)
            scriptSig = WeakReference(script)
        }
        return script
    }

    /** Set the given program as the scriptSig that is supposed to satisfy the connected output script.  */
    fun setScriptSig(scriptSig: Script) {
        this.scriptSig = WeakReference(checkNotNull(scriptSig))
        // TODO: This should all be cleaned up so we have a consistent internal representation.
        setScriptBytes(scriptSig.program)
    }

    /**
     * The "script bytes" might not actually be a script. In coinbase transactions where new coins are minted there
     * is no input transaction, so instead the scriptBytes contains some extra stuff (like a rollover nonce) that we
     * don't care about much. The bytes are turned into a Script object (cached below) on demand via a getter.
     * @return the scriptBytes
     */
    fun getScriptBytes(): ByteArray? {
        return scriptBytes
    }

    /** Clear input scripts, e.g. in preparation for signing.  */
    fun clearScriptBytes() {
        setScriptBytes(TransactionInput.EMPTY_ARRAY)
    }

    /**
     * @param scriptBytes the scriptBytes to set
     */
    internal fun setScriptBytes(scriptBytes: ByteArray?) {
        unCache()
        this.scriptSig = null
        val oldLength = length
        this.scriptBytes = scriptBytes
        // 40 = previous_outpoint (36) + sequence (4)
        val newLength = 40 + if (scriptBytes == null) 1 else VarInt.sizeOf(scriptBytes.size.toLong()) + scriptBytes.size
        adjustLength(newLength - oldLength)
    }

    enum class ConnectionResult {
        NO_SUCH_TX,
        ALREADY_SPENT,
        SUCCESS
    }

    // TODO: Clean all this up once TransactionOutPoint disappears.

    /**
     * Locates the referenced output from the given pool of transactions.
     *
     * @return The TransactionOutput or null if the transactions map doesn't contain the referenced tx.
     */
    internal fun getConnectedOutput(transactions: Map<Sha256Hash, Transaction>): TransactionOutput? {
        val tx = transactions[outpoint!!.hash] ?: return null
        return tx.getOutputs()[outpoint!!.index.toInt()]
    }

    /**
     * Alias for getOutpoint().getConnectedRedeemData(keyBag)
     * @see TransactionOutPoint.getConnectedRedeemData
     */
    @Throws(ScriptException::class)
    fun getConnectedRedeemData(keyBag: KeyBag): RedeemData? {
        return outpoint!!.getConnectedRedeemData(keyBag)
    }


    enum class ConnectMode {
        DISCONNECT_ON_CONFLICT,
        ABORT_ON_CONFLICT
    }

    /**
     * Connects this input to the relevant output of the referenced transaction if it's in the given map.
     * Connecting means updating the internal pointers and spent flags. If the mode is to ABORT_ON_CONFLICT then
     * the spent output won't be changed, but the outpoint.fromTx pointer will still be updated.
     *
     * @param transactions Map of txhash->transaction.
     * @param mode   Whether to abort if there's a pre-existing connection or not.
     * @return NO_SUCH_TX if the prevtx wasn't found, ALREADY_SPENT if there was a conflict, SUCCESS if not.
     */
    fun connect(transactions: Map<Sha256Hash, Transaction>, mode: ConnectMode): ConnectionResult {
        val tx = transactions[outpoint!!.hash] ?: return TransactionInput.ConnectionResult.NO_SUCH_TX
        return connect(tx, mode)
    }

    /**
     * Connects this input to the relevant output of the referenced transaction.
     * Connecting means updating the internal pointers and spent flags. If the mode is to ABORT_ON_CONFLICT then
     * the spent output won't be changed, but the outpoint.fromTx pointer will still be updated.
     *
     * @param transaction The transaction to try.
     * @param mode   Whether to abort if there's a pre-existing connection or not.
     * @return NO_SUCH_TX if transaction is not the prevtx, ALREADY_SPENT if there was a conflict, SUCCESS if not.
     */
    fun connect(transaction: Transaction, mode: ConnectMode): ConnectionResult {
        if (transaction.hash != outpoint!!.hash)
            return ConnectionResult.NO_SUCH_TX
        checkElementIndex(outpoint!!.index.toInt(), transaction.getOutputs().size, "Corrupt transaction")
        val out = transaction.getOutput(outpoint!!.index.toInt().toLong())
        if (!out.isAvailableForSpending) {
            if (parentTransaction == outpoint!!.fromTx) {
                // Already connected.
                return ConnectionResult.SUCCESS
            } else if (mode == ConnectMode.DISCONNECT_ON_CONFLICT) {
                out.markAsUnspent()
            } else if (mode == ConnectMode.ABORT_ON_CONFLICT) {
                outpoint!!.fromTx = out.parentTransaction
                return TransactionInput.ConnectionResult.ALREADY_SPENT
            }
        }
        connect(out)
        return TransactionInput.ConnectionResult.SUCCESS
    }

    /** Internal use only: connects this TransactionInput to the given output (updates pointers and spent flags)  */
    fun connect(out: TransactionOutput) {
        outpoint!!.fromTx = out.parentTransaction
        out.markAsSpent(this)
        value = out.getValue()
    }

    /**
     * If this input is connected, check the output is connected back to this input and release it if so, making
     * it spendable once again.
     *
     * @return true if the disconnection took place, false if it was not connected.
     */
    fun disconnect(): Boolean {
        if (outpoint!!.fromTx == null) return false
        val output = outpoint!!.fromTx!!.getOutput(outpoint!!.index.toInt().toLong())
        if (output.spentBy === this) {
            output.markAsUnspent()
            outpoint!!.fromTx = null
            return true
        } else {
            return false
        }
    }

    /**
     * @return true if this transaction's sequence number is set (ie it may be a part of a time-locked transaction)
     */
    fun hasSequence(): Boolean {
        return sequence != NO_SEQUENCE
    }

    /**
     * For a connected transaction, runs the script against the connected pubkey and verifies they are correct.
     * @throws ScriptException if the script did not verify.
     * @throws VerificationException If the outpoint doesn't match the given output.
     */
    @Throws(VerificationException::class)
    fun verify() {
        val fromTx = outpoint!!.fromTx
        val spendingIndex = outpoint!!.index
        checkNotNull(fromTx, "Not connected")
        val output = fromTx!!.getOutput(spendingIndex.toInt().toLong())
        verify(output)
    }

    /**
     * Verifies that this input can spend the given output. Note that this input must be a part of a transaction.
     * Also note that the consistency of the outpoint will be checked, even if this input has not been connected.
     *
     * @param output the output that this input is supposed to spend.
     * @throws ScriptException If the script doesn't verify.
     * @throws VerificationException If the outpoint doesn't match the given output.
     */
    @Throws(VerificationException::class)
    fun verify(output: TransactionOutput) {
        if (output.parent != null) {
            if (outpoint!!.hash != output.parentTransaction!!.hash)
                throw VerificationException("This input does not refer to the tx containing the output.")
            if (outpoint!!.index != output.index.toLong())
                throw VerificationException("This input refers to a different output on the given tx.")
        }
        val pubKey = output.getScriptPubKey()
        val myIndex = parentTransaction.getInputs().indexOf(this)
        getScriptSig().correctlySpends(parentTransaction, myIndex.toLong(), pubKey)
    }

    /** Returns a copy of the input detached from its containing transaction, if need be.  */
    fun duplicateDetached(): TransactionInput {
        return TransactionInput(params!!, null, bitcoinSerialize(), 0)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as TransactionInput?
        return (sequence == other!!.sequence && parent === other.parent
                && outpoint == other.outpoint && Arrays.equals(scriptBytes, other.scriptBytes))
    }

    override fun hashCode(): Int {
        return Objects.hashCode(sequence, outpoint, Arrays.hashCode(scriptBytes))
    }

    /**
     * Returns a human readable debug string.
     */
    override fun toString(): String {
        val s = StringBuilder("TxIn")
        try {
            if (isCoinBase) {
                s.append(": COINBASE")
            } else {
                s.append(" for [").append(outpoint).append("]: ").append(getScriptSig())
                val flags = Joiner.on(", ").skipNulls().join(
                        if (hasSequence()) "sequence: " + java.lang.Long.toHexString(sequence) else null,
                        if (isOptInFullRBF) "opts into full RBF" else null)
                if (!flags.isEmpty())
                    s.append(" (").append(flags).append(')')
            }
            return s.toString()
        } catch (e: ScriptException) {
            throw RuntimeException(e)
        }

    }

    companion object {
        /** Magic sequence number that indicates there is no sequence number.  */
        val NO_SEQUENCE = 0xFFFFFFFFL
        private val EMPTY_ARRAY = ByteArray(0)
        // Magic outpoint index that indicates the input is in fact unconnected.
        private val UNCONNECTED = 0xFFFFFFFFL
    }
}
/**
 * Creates an input that connects to nothing - used only in creation of coinbase transactions.
 */
