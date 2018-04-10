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

package org.bitcoinj.core.listeners

import org.bitcoinj.core.*

import javax.annotation.*
import java.util.*

/**
 *
 * Implementors can listen to events like blocks being downloaded/transactions being broadcast/connect/disconnects,
 * they can pre-filter messages before they are procesesed by a [Peer] or [PeerGroup], and they can
 * provide transactions to remote peers when they ask for them.
 */
interface GetDataEventListener {

    /**
     *
     * Called when a peer receives a getdata message, usually in response to an "inv" being broadcast. Return as many
     * items as possible which appear in the [GetDataMessage], or null if you're not interested in responding.
     *
     *
     * Note that this will never be called if registered with any executor other than
     * [org.bitcoinj.utils.Threading.SAME_THREAD]
     */
    fun getData(peer: Peer, m: GetDataMessage): List<Message>?
}
