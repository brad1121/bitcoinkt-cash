/*
 * Copyright 2011 Steve Coughlan.
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
 * Represents a Message type that can be contained within another Message.  ChildMessages that have a cached
 * backing byte array need to invalidate their parent's caches as well as their own if they are modified.
 *
 *
 * Instances of this class are not safe for use by multiple threads.
 */
abstract class ChildMessage : Message {

    var parent: Message? = null
        set(parent: Message?) {
        if (this.parent != null && this.parent !== parent && parent != null) {
            // After old parent is unlinked it won't be able to receive notice if this ChildMessage
            // changes internally.  To be safe we invalidate the parent cache to ensure it rebuilds
            // manually on serialization.
            this.parent!!.unCache()
        }
        this.parent = parent
    }

    @Deprecated("Use {@link #ChildMessage(NetworkParameters) instead.")
    protected constructor() {
    }

    constructor(params: NetworkParameters) : super(params) {}

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters?, payload: ByteArray?, offset: Int, protocolVersion: Int) : super(params, payload, offset, protocolVersion) {
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters?, payload: ByteArray?, offset: Int, protocolVersion: Int, parent: Message, setSerializer: MessageSerializer?, length: Int) : super(params, payload, offset, protocolVersion, setSerializer, length) {
        this.parent = parent
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters?, payload: ByteArray?, offset: Int) : super(params, payload, offset) {
    }

    @Throws(ProtocolException::class)
    constructor(params: NetworkParameters?, payload: ByteArray?, offset: Int, parent: Message?, setSerializer: MessageSerializer, length: Int) : super(params!!, payload!!, offset, setSerializer, length) {
        this.parent = parent
    }



    /* (non-Javadoc)
      * @see Message#unCache()
      */
    override fun unCache() {
        super.unCache()
        if (parent != null)
            parent!!.unCache()
    }

    protected fun adjustLength(adjustment: Int) {
        adjustLength(0, adjustment)
    }

    override fun adjustLength(newArraySize: Int, adjustment: Int) {
        super.adjustLength(newArraySize, adjustment)
        if (parent != null)
            parent!!.adjustLength(newArraySize, adjustment)
    }

}
