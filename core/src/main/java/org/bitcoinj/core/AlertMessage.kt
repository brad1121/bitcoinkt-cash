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

import java.util.Date
import java.util.HashSet

/**
 * Alerts are signed messages that are broadcast on the peer-to-peer network if they match a hard-coded signing key.
 * The private keys are held by a small group of core Bitcoin developers, and alerts may be broadcast in the event of
 * an available upgrade or a serious network problem. Alerts have an expiration time, data that specifies what
 * set of software versions it matches and the ability to cancel them by broadcasting another type of alert.
 *
 *
 *
 * The right course of action on receiving an alert is usually to either ensure a human will see it (display on screen,
 * log, email), or if you decide to use alerts for notifications that are specific to your app in some way, to parse it.
 * For example, you could treat it as an upgrade notification specific to your app. Satoshi designed alerts to ensure
 * that software upgrades could be distributed independently of a hard-coded website, in order to allow everything to
 * be purely peer-to-peer. You don't have to use this of course, and indeed it often makes more sense not to.
 *
 *
 *
 *
 * Before doing anything with an alert, you should check [AlertMessage.isSignatureValid].
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
class AlertMessage @Throws(ProtocolException::class)
constructor(params: NetworkParameters, payloadBytes: ByteArray) : Message(params, payloadBytes, 0) {
    private var content: ByteArray? = null
    private var signature: ByteArray? = null

    // See the getters for documentation of what each field means.
    var version: Long = 1
        private set
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //  Field accessors.

    /**
     * The time at which the alert should stop being broadcast across the network. Note that you can still receive
     * the alert after this time from other nodes if the alert still applies to them or to you.
     */
    var relayUntil: Date? = null
    /**
     * The time at which the alert ceases to be relevant. It should not be presented to the user or app administrator
     * after this time.
     */
    var expiration: Date? = null
    /**
     * The numeric identifier of this alert. Each alert should have a unique ID, but the signer can choose any number.
     * If an alert is broadcast with a cancel field higher than this ID, this alert is considered cancelled.
     * @return uint32
     */
    var id: Long = 0
    /**
     * A marker that results in any alerts with an ID lower than this value to be considered cancelled.
     * @return uint32
     */
    var cancel: Long = 0
    /**
     * The inclusive lower bound on software versions that are considered for the purposes of this alert. Bitcoin Core
     * compares this against a protocol version field, but as long as the subVer field is used to restrict it your
     * alerts could use any version numbers.
     * @return uint32
     */
    var minVer: Long = 0
    /**
     * The inclusive upper bound on software versions considered for the purposes of this alert. Bitcoin Core
     * compares this against a protocol version field, but as long as the subVer field is used to restrict it your
     * alerts could use any version numbers.
     */
    var maxVer: Long = 0
    /**
     * Provides an integer ordering amongst simultaneously active alerts.
     * @return uint32
     */
    var priority: Long = 0
    /**
     * This field is unused. It is presumably intended for the author of the alert to provide a justification for it
     * visible to protocol developers but not users.
     */
    var comment: String? = null
    /**
     * A string that is intended to display in the status bar of Bitcoin Core's GUI client. It contains the user-visible
     * message. English only.
     */
    var statusBar: String? = null
    /**
     * This field is never used.
     */
    var reserved: String? = null

    /**
     * Returns true if the digital signature attached to the message verifies. Don't do anything with the alert if it
     * doesn't verify, because that would allow arbitrary attackers to spam your users.
     */
    val isSignatureValid: Boolean
        get() = ECKey.verify(Sha256Hash.hashTwice(content), signature, params!!.alertSigningKey)

    override fun toString(): String {
        return "ALERT: " + statusBar!!
    }

    @Throws(ProtocolException::class)
    override fun parse() {
        // Alerts are formatted in two levels. The top level contains two byte arrays: a signature, and a serialized
        // data structure containing the actual alert data.
        val startPos = cursor
        content = readByteArray()
        signature = readByteArray()
        // Now we need to parse out the contents of the embedded structure. Rewind back to the start of the message.
        cursor = startPos
        readVarInt()  // Skip the length field on the content array.
        // We're inside the embedded structure.
        version = readUint32()
        // Read the timestamps. Bitcoin uses seconds since the epoch.
        relayUntil = Date(readUint64().toLong() * 1000)
        expiration = Date(readUint64().toLong() * 1000)
        id = readUint32()
        cancel = readUint32()
        // Sets are serialized as <len><item><item><item>....
        val cancelSetSize = readVarInt()
        if (cancelSetSize < 0 || cancelSetSize > MAX_SET_SIZE) {
            throw ProtocolException("Bad cancel set size: " + cancelSetSize)
        }
        // Using a hashset here is very inefficient given that this will normally be only one item. But Java doesn't
        // make it easy to do better. What we really want is just an array-backed set.
        val cancelSet = HashSet<Long>(cancelSetSize.toInt())
        for (i in 0 until cancelSetSize) {
            cancelSet.add(readUint32())
        }
        minVer = readUint32()
        maxVer = readUint32()
        // Read the subver matching set.
        val subverSetSize = readVarInt()
        if (subverSetSize < 0 || subverSetSize > MAX_SET_SIZE) {
            throw ProtocolException("Bad subver set size: " + subverSetSize)
        }
        val matchingSubVers = HashSet<String>(subverSetSize.toInt())
        for (i in 0 until subverSetSize) {
            matchingSubVers.add(readStr())
        }
        priority = readUint32()
        comment = readStr()
        statusBar = readStr()
        reserved = readStr()

        length = cursor - offset
    }

    companion object {

        // Chosen arbitrarily to avoid memory blowups.
        private val MAX_SET_SIZE: Long = 100
    }
}
