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

import com.google.common.base.Preconditions.checkArgument

import java.io.Serializable
import java.util.Arrays

import com.google.common.base.Objects
import com.google.common.primitives.Ints
import com.google.common.primitives.UnsignedBytes

/**
 *
 * In Bitcoin the following format is often used to represent some type of key:
 *
 *
 * <pre>[one version byte] [data bytes] [4 checksum bytes]</pre>
 *
 *
 *
 * and the result is then Base58 encoded. This format is used for addresses, and private keys exported using the
 * dumpprivkey command.
 */
open class VersionedChecksummedBytes : Serializable, Cloneable, Comparable<VersionedChecksummedBytes> {
    /**
     * Returns the "version" or "header" byte: the first byte of the data. This is used to disambiguate what the
     * contents apply to, for example, which network the key or address is valid on.
     *
     * @return A positive number between 0 and 255.
     */
    val version: Int
    protected var bytes: ByteArray

    @Throws(AddressFormatException::class)
    protected constructor(encoded: String) {
        val versionAndDataBytes = Base58.decodeChecked(encoded)
        val versionByte = versionAndDataBytes[0]
        version = versionByte and 0xFF
        bytes = ByteArray(versionAndDataBytes.size - 1)
        System.arraycopy(versionAndDataBytes, 1, bytes, 0, versionAndDataBytes.size - 1)
    }

    constructor(version: Int, bytes: ByteArray) {
        checkArgument(version >= 0 && version < 256)
        this.version = version
        this.bytes = bytes
    }

    /**
     * Returns the base-58 encoded String representation of this
     * object, including version and checksum bytes.
     */
    fun toBase58(): String {
        // A stringified buffer is:
        //   1 byte version + data bytes + 4 bytes check code (a truncated hash)
        val addressBytes = ByteArray(1 + bytes.size + 4)
        addressBytes[0] = version.toByte()
        System.arraycopy(bytes, 0, addressBytes, 1, bytes.size)
        val checksum = Sha256Hash.hashTwice(addressBytes, 0, bytes.size + 1)
        System.arraycopy(checksum, 0, addressBytes, bytes.size + 1, 4)
        return Base58.encode(addressBytes)
    }

    override fun toString(): String {
        return toBase58()
    }

    override fun hashCode(): Int {
        return Objects.hashCode(version, Arrays.hashCode(bytes))
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val other = o as VersionedChecksummedBytes?
        return this.version == other!!.version && Arrays.equals(this.bytes, other.bytes)
    }

    /**
     * {@inheritDoc}
     *
     * This implementation narrows the return type to `VersionedChecksummedBytes`
     * and allows subclasses to throw `CloneNotSupportedException` even though it
     * is never thrown by this implementation.
     */
    @Throws(CloneNotSupportedException::class)
    public override fun clone(): VersionedChecksummedBytes {
        return super.clone() as VersionedChecksummedBytes
    }

    /**
     * {@inheritDoc}
     *
     * This implementation uses an optimized Google Guava method to compare `bytes`.
     */
    override fun compareTo(o: VersionedChecksummedBytes): Int {
        val result = Ints.compare(this.version, o.version)
        return if (result != 0) result else UnsignedBytes.lexicographicalComparator().compare(this.bytes, o.bytes)
    }
}
