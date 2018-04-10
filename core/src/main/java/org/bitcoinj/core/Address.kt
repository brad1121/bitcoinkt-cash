/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Giannis Dzegoutanis
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
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

import org.bitcoinj.params.Networks
import org.bitcoinj.script.Script

import com.google.common.base.Preconditions.checkArgument
import com.google.common.base.Preconditions.checkNotNull

/**
 *
 * A Bitcoin address looks like 1MsScoe2fTJoq4ZPdQgqyhgWeoNamYPevy and is derived from an elliptic curve public key
 * plus a set of network parameters. Not to be confused with a [PeerAddress] or [AddressMessage]
 * which are about network (TCP) addresses.
 *
 *
 * A standard address is built by taking the RIPE-MD160 hash of the public key bytes, with a version prefix and a
 * checksum suffix, then encoding it textually as base58. The version prefix is used to both denote the network for
 * which the address is valid (see [NetworkParameters], and also to indicate how the bytes inside the address
 * should be interpreted. Whilst almost all addresses today are hashes of public keys, another (currently unsupported
 * type) can contain a hash of a script instead.
 */
class Address : VersionedChecksummedBytes {

    /**
     * Examines the version byte of the address and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet. You should be able to handle a null response from this method. Note that the
     * parameters returned is not necessarily the same as the one the Address was created with.
     *
     * @return a NetworkParameters representing the network the address is intended for.
     */
    @Transient
    var parameters: NetworkParameters? = null
        private set

    /** The (big endian) 20 byte hash that is the core of a Bitcoin address.  */
    val hash160: ByteArray
        get() = bytes

    /**
     * Returns true if this address is a Pay-To-Script-Hash (P2SH) address.
     * See also https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki: Address Format for pay-to-script-hash
     */
    val isP2SHAddress: Boolean
        get() {
            val parameters = parameters
            return parameters != null && this.version == parameters.p2SHHeader
        }

    /**
     * Construct an address from parameters, the address version, and the hash160 form. Example:
     *
     *
     *
     * <pre>new Address(MainNetParams.get(), NetworkParameters.getAddressHeader(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    @Throws(WrongNetworkException::class)
    constructor(params: NetworkParameters, version: Int, hash160: ByteArray) : super(version, hash160) {
        checkNotNull(params)
        checkArgument(hash160.size == 20, "Addresses are 160-bit hashes, so you must provide 20 bytes")
        if (!isAcceptableVersion(params, version))
            throw WrongNetworkException(version, params.acceptableAddressCodes)
        this.parameters = params
    }

    /**
     * Construct an address from parameters and the hash160 form. Example:
     *
     *
     *
     * <pre>new Address(MainNetParams.get(), Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));</pre>
     */
    constructor(params: NetworkParameters, hash160: ByteArray) : super(params.addressHeader, hash160) {
        checkArgument(hash160.size == 20, "Addresses are 160-bit hashes, so you must provide 20 bytes")
        this.parameters = params
    }


    @Deprecated("Use {@link #fromBase58(NetworkParameters, String)} ")
    @Throws(AddressFormatException::class)
    constructor(params: NetworkParameters?, address: String) : super(address) {
        if (params != null) {
            if (!isAcceptableVersion(params, version)) {
                throw WrongNetworkException(version, params.acceptableAddressCodes)
            }
            this.parameters = params
        } else {
            var paramsFound: NetworkParameters? = null
            for (p in Networks.get()) {
                if (isAcceptableVersion(p, version)) {
                    paramsFound = p
                    break
                }
            }
            if (paramsFound == null)
                throw AddressFormatException("No network found for " + address)

            this.parameters = paramsFound
        }
    }

    /**
     * This implementation narrows the return type to `Address`.
     */
    @Throws(CloneNotSupportedException::class)
    override fun clone(): Address {
        return super.clone() as Address
    }

    // Java serialization

    @Throws(IOException::class)
    private fun writeObject(out: ObjectOutputStream) {
        out.defaultWriteObject()
        out.writeUTF(parameters!!.id)
    }

    @Throws(IOException::class, ClassNotFoundException::class)
    private fun readObject(`in`: ObjectInputStream) {
        `in`.defaultReadObject()
        parameters = NetworkParameters.fromID(`in`.readUTF())
    }

    companion object {
        /**
         * An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
         */
        val LENGTH = 20

        /** Returns an Address that represents the given P2SH script hash.  */
        fun fromP2SHHash(params: NetworkParameters, hash160: ByteArray): Address {
            try {
                return Address(params, params.p2SHHeader, hash160)
            } catch (e: WrongNetworkException) {
                throw RuntimeException(e)  // Cannot happen.
            }

        }

        /** Returns an Address that represents the script hash extracted from the given scriptPubKey  */
        fun fromP2SHScript(params: NetworkParameters, scriptPubKey: Script): Address {
            checkArgument(scriptPubKey.isPayToScriptHash, "Not a P2SH script")
            return fromP2SHHash(params, scriptPubKey.pubKeyHash)
        }

        /**
         * Construct an address from its Base58 representation.
         * @param params
         * The expected NetworkParameters or null if you don't want validation.
         * @param base58
         * The textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL".
         * @throws AddressFormatException
         * if the given base58 doesn't parse or the checksum is invalid
         * @throws WrongNetworkException
         * if the given address is valid but for a different chain (eg testnet vs mainnet)
         */
        @Throws(AddressFormatException::class)
        fun fromBase58(params: NetworkParameters?, base58: String): Address {
            return Address(params, base58)
        }

        /**
         * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
         * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
         * compatible with the current wallet.
         * @return a NetworkParameters of the address
         * @throws AddressFormatException if the string wasn't of a known version
         */
        @Throws(AddressFormatException::class)
        fun getParametersFromAddress(address: String): NetworkParameters? {
            try {
                return Address.fromBase58(null, address).parameters
            } catch (e: WrongNetworkException) {
                throw RuntimeException(e)  // Cannot happen.
            }

        }

        /**
         * Check if a given address version is valid given the NetworkParameters.
         */
        private fun isAcceptableVersion(params: NetworkParameters, version: Int): Boolean {
            for (v in params.acceptableAddressCodes!!) {
                if (version == v) {
                    return true
                }
            }
            return false
        }
    }
}
