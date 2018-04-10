/*
 * Copyright 2013 Matt Corallo
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
import java.io.IOException
import java.io.OutputStream
import java.util.Locale

/**
 *
 * A message sent by nodes when a message we sent was rejected (ie a transaction had too little fee/was invalid/etc).
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class RejectMessage : Message {

    /**
     * Provides the type of message which was rejected by the peer.
     * Note that this is ENTIRELY UNTRUSTED and should be sanity-checked before it is printed or processed.
     */
    var rejectedMessage: String? = null
        private set
    /**
     * The reason message given for rejection.
     * Note that this is ENTIRELY UNTRUSTED and should be sanity-checked before it is printed or processed.
     */
    var reasonString: String? = null
        private set
    /**
     * The reason code given for why the peer rejected the message.
     */
    var reasonCode: RejectCode? = null
        private set
    /**
     * Provides the hash of the rejected object (if getRejectedMessage() is either "tx" or "block"), otherwise null.
     */
    var rejectedObjectHash: Sha256Hash? = null
        private set

    enum class RejectCode private constructor(internal var code: Byte) {
        /** The message was not able to be parsed  */
        MALFORMED(0x01.toByte()),
        /** The message described an invalid object  */
        INVALID(0x10.toByte()),
        /** The message was obsolete or described an object which is obsolete (eg unsupported, old version, v1 block)  */
        OBSOLETE(0x11.toByte()),
        /**
         * The message was relayed multiple times or described an object which is in conflict with another.
         * This message can describe errors in protocol implementation or the presence of an attempt to DOUBLE SPEND.
         */
        DUPLICATE(0x12.toByte()),
        /**
         * The message described an object was not standard and was thus not accepted.
         * Bitcoin Core has a concept of standard transaction forms, which describe scripts and encodings which
         * it is willing to relay further. Other transactions are neither relayed nor mined, though they are considered
         * valid if they appear in a block.
         */
        NONSTANDARD(0x40.toByte()),
        /**
         * This refers to a specific form of NONSTANDARD transactions, which have an output smaller than some constant
         * defining them as dust (this is no longer used).
         */
        DUST(0x41.toByte()),
        /** The messages described an object which did not have sufficient fee to be relayed further.  */
        INSUFFICIENTFEE(0x42.toByte()),
        /** The message described a block which was invalid according to hard-coded checkpoint blocks.  */
        CHECKPOINT(0x43.toByte()),
        OTHER(0xff.toByte());


        companion object {
            internal fun fromCode(code: Byte): RejectCode {
                for (rejectCode in RejectCode.values())
                    if (rejectCode.code == code)
                        return rejectCode
                return OTHER
            }
        }
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, payload: ByteArray) : super(params, payload, 0) {
    }

    /** Constructs a reject message that fingers the object with the given hash as rejected for the given reason.  */
    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters, code: RejectCode, hash: Sha256Hash, message: String, reason: String) : super(params) {
        this.reasonCode = code
        this.rejectedObjectHash = hash
        this.rejectedMessage = message
        this.reasonString = reason
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        rejectedMessage = readStr()
        reasonCode = RejectCode.fromCode(readBytes(1)[0])
        reasonString = readStr()
        if (rejectedMessage == "block" || rejectedMessage == "tx")
            rejectedObjectHash = readHash()
        length = cursor - offset
    }

    @Throws(IOException::class)
    public override fun bitcoinSerializeToStream(stream: OutputStream) {
        val messageBytes = rejectedMessage!!.toByteArray(charset("UTF-8"))
        stream.write(VarInt(messageBytes.size.toLong()).encode())
        stream.write(messageBytes)
        stream.write(reasonCode!!.code.toInt())
        val reasonBytes = reasonString!!.toByteArray(charset("UTF-8"))
        stream.write(VarInt(reasonBytes.size.toLong()).encode())
        stream.write(reasonBytes)
        if ("block" == rejectedMessage || "tx" == rejectedMessage)
            stream.write(rejectedObjectHash!!.reversedBytes)
    }


    /**
     * A String representation of the relevant details of this reject message.
     * Be aware that the value returned by this method includes the value returned by
     * [getReasonString][.getReasonString], which is taken from the reject message unchecked.
     * Through malice or otherwise, it might contain control characters or other harmful content.
     */
    override fun toString(): String {
        val hash = rejectedObjectHash
        return String.format(Locale.US, "Reject: %s %s for reason '%s' (%d)", rejectedMessage,
                hash ?: "", reasonString, reasonCode!!.code)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as RejectMessage?
        return (rejectedMessage == other!!.rejectedMessage && reasonCode == other.reasonCode
                && reasonString == other.reasonString && rejectedObjectHash == other.rejectedObjectHash)
    }

    override fun hashCode(): Int {
        return Objects.hashCode(rejectedMessage, reasonCode, reasonString, rejectedObjectHash)
    }
}
