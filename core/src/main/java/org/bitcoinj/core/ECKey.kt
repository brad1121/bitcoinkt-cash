/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2014-2016 the libsecp256k1 contributors
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

import org.bitcoinj.crypto.*
import com.google.common.annotations.VisibleForTesting
import com.google.common.base.MoreObjects
import com.google.common.base.Objects
import com.google.common.base.Preconditions
import com.google.common.primitives.Ints
import com.google.common.primitives.UnsignedBytes
import org.bitcoin.NativeSecp256k1
import org.bitcoin.NativeSecp256k1Util
import org.bitcoin.Secp256k1Context
import org.bitcoinj.wallet.Protos
import org.bitcoinj.wallet.Wallet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.spongycastle.asn1.*
import org.spongycastle.asn1.x9.X9ECParameters
import org.spongycastle.asn1.x9.X9IntegerConverter
import org.spongycastle.crypto.AsymmetricCipherKeyPair
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.ec.CustomNamedCurves
import org.spongycastle.crypto.generators.ECKeyPairGenerator
import org.spongycastle.crypto.params.*
import org.spongycastle.crypto.signers.ECDSASigner
import org.spongycastle.crypto.signers.HMacDSAKCalculator
import org.spongycastle.math.ec.ECAlgorithms
import org.spongycastle.math.ec.ECPoint
import org.spongycastle.math.ec.FixedPointCombMultiplier
import org.spongycastle.math.ec.FixedPointUtil
import org.spongycastle.math.ec.custom.sec.SecP256K1Curve
import org.spongycastle.util.encoders.Base64
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.SignatureException
import java.util.Arrays
import java.util.Comparator

import com.google.common.base.Preconditions.*

import kotlin.experimental.and

// TODO: Move this class to tracking compression state itself.
// The Bouncy Castle developers are deprecating their own tracking of the compression state.

/**
 *
 * Represents an elliptic curve public and (optionally) private key, usable for digital signatures but not encryption.
 * Creating a new ECKey with the empty constructor will generate a new random keypair. Other static methods can be used
 * when you already have the public or private parts. If you create a key with only the public part, you can check
 * signatures but not create them.
 *
 *
 * ECKey also provides access to Bitcoin Core compatible text message signing, as accessible via the UI or JSON-RPC.
 * This is slightly different to signing raw bytes - if you want to sign your own data and it won't be exposed as
 * text to people, you don't want to use this. If in doubt, ask on the mailing list.
 *
 *
 * The ECDSA algorithm supports *key recovery* in which a signature plus a couple of discriminator bits can
 * be reversed to find the public key used to calculate it. This can be convenient when you have a message and a
 * signature and want to find out who signed it, rather than requiring the user to provide the expected identity.
 *
 *
 * This class supports a variety of serialization forms. The methods that accept/return byte arrays serialize
 * private keys as raw byte arrays and public keys using the SEC standard byte encoding for public keys. Signatures
 * are encoded using ASN.1/DER inside the Bitcoin protocol.
 *
 *
 * A key can be *compressed* or *uncompressed*. This refers to whether the public key is represented
 * when encoded into bytes as an (x, y) coordinate on the elliptic curve, or whether it's represented as just an X
 * co-ordinate and an extra byte that carries a sign bit. With the latter form the Y coordinate can be calculated
 * dynamically, however, **because the binary serialization is different the address of a key changes if its
 * compression status is changed**. If you deviate from the defaults it's important to understand this: money sent
 * to a compressed version of the key will have a different address to the same key in uncompressed form. Whether
 * a public key is compressed or not is recorded in the SEC binary serialisation format, and preserved in a flag in
 * this class so round-tripping preserves state. Unless you're working with old software or doing unusual things, you
 * can usually ignore the compressed/uncompressed distinction.
 */
open class ECKey : EncryptableItem {

    // The two parts of the key. If "priv" is set, "pub" can always be calculated. If "pub" is set but not "priv", we
    // can only verify signatures not make them.
    protected val priv: BigInteger  // A field element.
    protected val pub: LazyECPoint

    // Creation time of the key in seconds since the epoch, or zero if the key was deserialized from a version that did
    // not have this field.
    protected var creationTimeSeconds: Long
    /**
     * Returns the creation time of this key or zero if the key was deserialized from a version that did not store
     * that data.
     */
       get(): Long {
            return creationTimeSeconds
        }

    /**
     * Sets the creation time of this key. Zero is a convention to mean "unavailable". This method can be useful when
     * you have a raw key you are importing from somewhere else.
     */
     set(newCreationTimeSeconds: Long) {
        if (newCreationTimeSeconds < 0)
            throw IllegalArgumentException("Cannot set creation time to negative value: " + newCreationTimeSeconds)
        creationTimeSeconds = newCreationTimeSeconds
    }
    /**
     * Returns the KeyCrypter that was used to encrypt to encrypt this ECKey. You need this to decrypt the ECKey.
     */
    open var keyCrypter: KeyCrypter? = null
        protected set
    /**
     * Returns the the encrypted private key bytes and initialisation vector for this ECKey, or null if the ECKey
     * is not encrypted.
     */
    var encryptedPrivateKey: EncryptedData? = null
        protected set

    private var pubKeyHash: ByteArray? = null

    /**
     * Returns true if this key doesn't have unencrypted access to private key bytes. This may be because it was never
     * given any private key bytes to begin with (a watching key), or because the key is encrypted. You can use
     * [.isEncrypted] to tell the cases apart.
     */
    open val isPubKeyOnly: Boolean
        get() = priv == null

    /** Returns true if this key is watch only, meaning it has a public key but no private key.  */
    val isWatching: Boolean
        get() = isPubKeyOnly && !isEncrypted

    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is **not** the same
     * as the pubKeyHash/address.
     */
    val pubKey: ByteArray
        get() = pub!!.encoded

    /** Gets the public key in the form of an elliptic curve point object from Bouncy Castle.  */
    val pubKeyPoint: ECPoint
        get() = pub!!.get()

    /**
     * Gets the private key in the form of an integer field element. The public key is derived by performing EC
     * point addition this number of times (i.e. point multiplying).
     *
     * @throws java.lang.IllegalStateException if the private key bytes are not available.
     */
    open val privKey: BigInteger
        get() {
            if (priv == null)
                throw MissingPrivateKeyException()
            return priv
        }

    /**
     * Returns whether this key is using the compressed form or not. Compressed pubkeys are only 33 bytes, not 64.
     */
    val isCompressed: Boolean
        get() = pub.isCompressed

    /**
     * Returns a 32 byte array containing the private key.
     * @throws org.bitcoinj.core.ECKey.MissingPrivateKeyException if the private key bytes are missing/encrypted.
     */
    val privKeyBytes: ByteArray?
        get() = Utils.bigIntegerToBytes(privKey, 32)

    val privateKeyAsHex: String
        get() = Utils.HEX.encode(privKeyBytes!!)

    val publicKeyAsHex: String
        get() = Utils.HEX.encode(pub.encoded)

    /**
     * Generates an entirely new keypair with the given [SecureRandom] object. Point compression is used so the
     * resulting public key will be 33 bytes (32 for the co-ordinate and 1 byte to represent the y bit).
     */
    constructor(){
        ECKey(secureRandom)
    }
    constructor(secureRandom: SecureRandom) {
        val generator = ECKeyPairGenerator()
        val keygenParams = ECKeyGenerationParameters(CURVE, secureRandom)
        generator.init(keygenParams)
        val keypair = generator.generateKeyPair()
        val privParams = keypair.private as ECPrivateKeyParameters
        val pubParams = keypair.public as ECPublicKeyParameters
        this.priv = privParams.d
        this.pub = LazyECPoint(CURVE.curve, pubParams.q.getEncoded(true))
        creationTimeSeconds = Utils.currentTimeSeconds()
    }

    protected constructor(priv: BigInteger?, pub: ECPoint) {
        if (priv != null) {
            // Try and catch buggy callers or bad key imports, etc. Zero and one are special because these are often
            // used as sentinel values and because scripting languages have a habit of auto-casting true and false to
            // 1 and 0 or vice-versa. Type confusion bugs could therefore result in private keys with these values.
            checkArgument(priv != BigInteger.ZERO)
            checkArgument(priv != BigInteger.ONE)
        }
        this.priv = priv!!
        this.pub = LazyECPoint(checkNotNull(pub))
    }

    protected constructor(priv: BigInteger?, pub: LazyECPoint) {
        this.priv = priv!!
        this.pub = checkNotNull(pub)
    }

    /**
     * Returns a copy of this key, but with the public point represented in uncompressed form. Normally you would
     * never need this: it's for specialised scenarios or when backwards compatibility in encoded form is necessary.
     */
    fun decompress(): ECKey {
        return if (!pub.isCompressed)
            this
        else
            ECKey(priv, decompressPoint(pub.get()))
    }

    /**
     * Creates an ECKey given only the private key bytes. This is the same as using the BigInteger constructor, but
     * is more convenient if you are importing a key from elsewhere. The public key will be automatically derived
     * from the private key.
     */
    @Deprecated("")
    constructor(privKeyBytes: ByteArray?, pubKey: ByteArray?) : this(if (privKeyBytes == null) null else BigInteger(1, privKeyBytes), pubKey) {
    }

    /**
     * Create a new ECKey with an encrypted private key, a public key and a KeyCrypter.
     *
     * @param encryptedPrivateKey The private key, encrypted,
     * @param pubKey The keys public key
     * @param keyCrypter The KeyCrypter that will be used, with an AES key, to encrypt and decrypt the private key
     */
    @Deprecated("")
    constructor(encryptedPrivateKey: EncryptedData, pubKey: ByteArray, keyCrypter: KeyCrypter) : this(null as ByteArray?, pubKey) {

        this.keyCrypter = checkNotNull(keyCrypter)
        this.encryptedPrivateKey = encryptedPrivateKey
    }

    /**
     * Creates an ECKey given either the private key only, the public key only, or both. If only the private key
     * is supplied, the public key will be calculated from it (this is slow). If both are supplied, it's assumed
     * the public key already correctly matches the private key. If only the public key is supplied, this ECKey cannot
     * be used for signing.
     * @param compressed If set to true and pubKey is null, the derived public key will be in compressed form.
     */
    @Deprecated("")
    constructor(privKey: BigInteger?, pubKey: ByteArray?, compressed: Boolean) {
        if (privKey == null && pubKey == null)
            throw IllegalArgumentException("ECKey requires at least private or public key")
        this.priv = privKey!!
        if (pubKey == null) {
            // Derive public from private.
            var point = publicPointFromPrivate(privKey!!)
            point = getPointWithCompression(point, compressed)
            this.pub = LazyECPoint(point)
        } else {
            // We expect the pubkey to be in regular encoded form, just as a BigInteger. Therefore the first byte is
            // a special marker byte.
            // TODO: This is probably not a useful API and may be confusing.
            this.pub = LazyECPoint(CURVE.curve, pubKey)
        }
    }

    /**
     * Creates an ECKey given either the private key only, the public key only, or both. If only the private key
     * is supplied, the public key will be calculated from it (this is slow). If both are supplied, it's assumed
     * the public key already correctly matches the public key. If only the public key is supplied, this ECKey cannot
     * be used for signing.
     */
    @Deprecated("")
    private constructor(privKey: BigInteger?, pubKey: ByteArray?) : this(privKey, pubKey, false) {
    }

    /**
     * Returns true if this key has unencrypted access to private key bytes. Does the opposite of
     * [.isPubKeyOnly].
     */
    open fun hasPrivKey(): Boolean {
        return priv != null
    }

    /**
     * Output this ECKey as an ASN.1 encoded private key, as understood by OpenSSL or used by Bitcoin Core
     * in its wallet storage format.
     * @throws org.bitcoinj.core.ECKey.MissingPrivateKeyException if the private key is missing or encrypted.
     */
    fun toASN1(): ByteArray {
        try {
            val privKeyBytes = privKeyBytes
            val baos = ByteArrayOutputStream(400)

            // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
            //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
            //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
            // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
            val seq = DERSequenceGenerator(baos)
            seq.addObject(ASN1Integer(1)) // version
            seq.addObject(DEROctetString(privKeyBytes!!))
            seq.addObject(DERTaggedObject(0, CURVE_PARAMS.toASN1Primitive()))
            seq.addObject(DERTaggedObject(1, DERBitString(pubKey)))
            seq.close()
            return baos.toByteArray()
        } catch (e: IOException) {
            throw RuntimeException(e)  // Cannot happen, writing to memory stream.
        }

    }

    /** Gets the hash160 form of the public key (as seen in addresses).  */
    fun getPubKeyHash(): ByteArray {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256hash160(this.pub.encoded)
        return pubKeyHash as ByteArray
    }

    /**
     * Returns the address that corresponds to the public part of this ECKey. Note that an address is derived from
     * the RIPEMD-160 hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    fun toAddress(params: NetworkParameters): Address {
        return Address(params, getPubKeyHash())
    }

    /**
     * Groups the two components that make up a signature, and provides a way to encode to DER form, which is
     * how ECDSA signatures are represented when embedded in other data structures in the Bitcoin protocol. The raw
     * components can be useful for doing further EC maths on them.
     */
    open class ECDSASignature
    /**
     * Constructs a signature with the given components. Does NOT automatically canonicalise the signature.
     */
    (
            /** The two components of the signature.  */
            val r: BigInteger, val s: BigInteger) {

        /**
         * Returns true if the S component is "low", that means it is below [ECKey.HALF_CURVE_ORDER]. See [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures).
         */
        val isCanonical: Boolean
            get() = s.compareTo(HALF_CURVE_ORDER) <= 0

        /**
         * Will automatically adjust the S component to be less than or equal to half the curve order, if necessary.
         * This is required because for every signature (r,s) the signature (r, -s (mod N)) is a valid signature of
         * the same message. However, we dislike the ability to modify the bits of a Bitcoin transaction after it's
         * been signed, as that violates various assumed invariants. Thus in future only one of those forms will be
         * considered legal and the other will be banned.
         */
        open fun toCanonicalised(): ECDSASignature {
            return if (!isCanonical) {
                // The order of the curve is the number of valid points that exist on that curve. If S is in the upper
                // half of the number of valid points, then bring it back to the lower half. Otherwise, imagine that
                //    N = 10
                //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
                //    10 - 8 == 2, giving us always the latter solution, which is canonical.
                ECDSASignature(r, CURVE.n.subtract(s))
            } else {
                this
            }
        }

        /**
         * DER is an international standard for serializing data structures which is widely used in cryptography.
         * It's somewhat like protocol buffers but less convenient. This method returns a standard DER encoding
         * of the signature, as recognized by OpenSSL and other libraries.
         */
        fun encodeToDER(): ByteArray {
            try {
                return derByteStream().toByteArray()
            } catch (e: IOException) {
                throw RuntimeException(e)  // Cannot happen.
            }

        }

        @Throws(IOException::class)
        protected fun derByteStream(): ByteArrayOutputStream {
            // Usually 70-72 bytes.
            val bos = ByteArrayOutputStream(72)
            val seq = DERSequenceGenerator(bos)
            seq.addObject(ASN1Integer(r))
            seq.addObject(ASN1Integer(s))
            seq.close()
            return bos
        }

        override fun equals(o: Any?): Boolean {
            if (this === o) return true
            if (o == null || javaClass != o.javaClass) return false
            val other = o as ECDSASignature?
            return r == other!!.r && s == other.s
        }

        override fun hashCode(): Int {
            return Objects.hashCode(r, s)
        }

        companion object {

            fun decodeFromDER(bytes: ByteArray): ECDSASignature {
                var decoder: ASN1InputStream? = null
                try {
                    decoder = ASN1InputStream(bytes)
                    val seq = decoder.readObject() as DLSequence ?: throw RuntimeException("Reached past end of ASN.1 stream.")
                    val r: ASN1Integer
                    val s: ASN1Integer
                    try {
                        r = seq.getObjectAt(0) as ASN1Integer
                        s = seq.getObjectAt(1) as ASN1Integer
                    } catch (e: ClassCastException) {
                        throw IllegalArgumentException(e)
                    }

                    // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
                    // Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html
                    return ECDSASignature(r.positiveValue, s.positiveValue)
                } catch (e: IOException) {
                    throw RuntimeException(e)
                } finally {
                    if (decoder != null)
                        try {
                            decoder.close()
                        } catch (x: IOException) {
                        }

                }
            }
        }
    }

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using ASN.1 format, so you want [org.bitcoinj.core.ECKey.ECDSASignature.toASN1]
     * instead. However sometimes the independent components can be useful, for instance, if you're going to do
     * further EC maths on them.
     * @throws KeyCrypterException if this ECKey doesn't have a private part.
     */
    @Throws(KeyCrypterException::class)
    fun sign(input: Sha256Hash): ECDSASignature {
        return sign(input, null)
    }

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Bitcoin protocol, they are
     * usually encoded using DER format, so you want [org.bitcoinj.core.ECKey.ECDSASignature.encodeToDER]
     * instead. However sometimes the independent components can be useful, for instance, if you're doing to do further
     * EC maths on them.
     *
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     * @throws KeyCrypterException if there's something wrong with aesKey.
     * @throws ECKey.MissingPrivateKeyException if this key cannot sign because it's pubkey only.
     */
    @Throws(KeyCrypterException::class)
    open fun sign(input: Sha256Hash, aesKey: KeyParameter?): ECDSASignature {
        val crypter = keyCrypter
        if (crypter != null) {
            if (aesKey == null)
                throw KeyIsEncryptedException()
            return decrypt(aesKey).sign(input)
        } else {
            // No decryption of private key required.
            if (priv == null)
                throw MissingPrivateKeyException()
        }
        return doSign(input, priv)
    }

    protected fun doSign(input: Sha256Hash, privateKeyForSigning: BigInteger): ECDSASignature {
        if (Secp256k1Context.isEnabled()) {
            try {
                val signature = NativeSecp256k1.sign(
                        input.bytes,
                        Utils.bigIntegerToBytes(privateKeyForSigning, 32)
                )
                return ECDSASignature.decodeFromDER(signature)
            } catch (e: NativeSecp256k1Util.AssertFailException) {
                log.error("Caught AssertFailException inside secp256k1", e)
                throw RuntimeException(e)
            }

        }
        if (FAKE_SIGNATURES)
            return TransactionSignature.dummy()
        checkNotNull(privateKeyForSigning)
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        val privKey = ECPrivateKeyParameters(privateKeyForSigning, CURVE)
        signer.init(true, privKey)
        val components = signer.generateSignature(input.bytes)
        return ECDSASignature(components[0], components[1]).toCanonicalised()
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param hash      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     */
    fun verify(hash: ByteArray, signature: ByteArray): Boolean {
        return ECKey.verify(hash, signature, pubKey)
    }

    /**
     * Verifies the given R/S pair (signature) against a hash using the public key.
     */
    fun verify(sigHash: Sha256Hash, signature: ECDSASignature): Boolean {
        return ECKey.verify(sigHash.bytes, signature, pubKey)
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key, and throws an exception
     * if the signature doesn't match
     * @throws java.security.SignatureException if the signature does not match.
     */
    @Throws(SignatureException::class)
    fun verifyOrThrow(hash: ByteArray, signature: ByteArray) {
        if (!verify(hash, signature))
            throw SignatureException()
    }

    /**
     * Verifies the given R/S pair (signature) against a hash using the public key, and throws an exception
     * if the signature doesn't match
     * @throws java.security.SignatureException if the signature does not match.
     */
    @Throws(SignatureException::class)
    fun verifyOrThrow(sigHash: Sha256Hash, signature: ECDSASignature) {
        if (!ECKey.verify(sigHash.bytes, signature, pubKey))
            throw SignatureException()
    }

    /**
     * Signs a text message using the standard Bitcoin messaging signing format and returns the signature as a base64
     * encoded string.
     *
     * @throws IllegalStateException if this ECKey does not have the private part.
     * @throws KeyCrypterException if this ECKey is encrypted and no AESKey is provided or it does not decrypt the ECKey.
     */
    @Throws(KeyCrypterException::class)
    @JvmOverloads
    fun signMessage(message: String, aesKey: KeyParameter? = null): String {
        val data = Utils.formatMessageForSigning(message)
        val hash = Sha256Hash.twiceOf(data)
        val sig = sign(hash, aesKey)
        // Now we have to work backwards to figure out the recId needed to recover the signature.
        var recId = -1
        for (i in 0..3) {
            val k = ECKey.recoverFromSignature(i, sig, hash, isCompressed)
            if (k != null && k.pub == pub) {
                recId = i
                break
            }
        }
        if (recId == -1)
            throw RuntimeException("Could not construct a recoverable key. This should never happen.")
        val headerByte = recId + 27 + if (isCompressed) 4 else 0
        val sigData = ByteArray(65)  // 1 header + 32 bytes for R + 32 bytes for S
        sigData[0] = headerByte.toByte()
        System.arraycopy(Utils.bigIntegerToBytes(sig.r, 32)!!, 0, sigData, 1, 32)
        System.arraycopy(Utils.bigIntegerToBytes(sig.s, 32)!!, 0, sigData, 33, 32)
        return String(Base64.encode(sigData), Charset.forName("UTF-8"))
    }

    /**
     * Convenience wrapper around [ECKey.signedMessageToKey]. If the key derived from the
     * signature is not the same as this one, throws a SignatureException.
     */
    @Throws(SignatureException::class)
    fun verifyMessage(message: String, signatureBase64: String) {
        val key = ECKey.signedMessageToKey(message, signatureBase64)
        if (key.pub != pub)
            throw SignatureException("Signature did not match for message")
    }

    /**
     * Exports the private key in the form used by Bitcoin Core's "dumpprivkey" and "importprivkey" commands. Use
     * the [org.bitcoinj.core.DumpedPrivateKey.toString] method to get the string.
     *
     * @param params The network this key is intended for use on.
     * @return Private key bytes as a [DumpedPrivateKey].
     * @throws IllegalStateException if the private key is not available.
     */
    fun getPrivateKeyEncoded(params: NetworkParameters?): DumpedPrivateKey {
        return DumpedPrivateKey(params!!, privKeyBytes!!, isCompressed)
    }



    /**
     * Create an encrypted private key with the keyCrypter and the AES key supplied.
     * This method returns a new encrypted key and leaves the original unchanged.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the encrypted bytes are created.
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached as it is slow to create).
     * @return encryptedKey
     */
    @Throws(KeyCrypterException::class)
    open fun encrypt(keyCrypter: KeyCrypter, aesKey: KeyParameter): ECKey {
        checkNotNull(keyCrypter)
        val privKeyBytes = privKeyBytes
        val encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, aesKey)
        val result = ECKey.fromEncrypted(encryptedPrivateKey, keyCrypter, pubKey)
        result.creationTimeSeconds =(creationTimeSeconds)
        return result
    }

    /**
     * Create a decrypted private key with the keyCrypter and AES key supplied. Note that if the aesKey is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param keyCrypter The keyCrypter that specifies exactly how the decrypted bytes are created.
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    @Throws(KeyCrypterException::class)
    open fun decrypt(keyCrypter: KeyCrypter, aesKey: KeyParameter): ECKey {
        checkNotNull(keyCrypter)
        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && this.keyCrypter != keyCrypter)
            throw KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it")
        checkState(encryptedPrivateKey != null, "This key is not encrypted")
        val unencryptedPrivateKey = keyCrypter.decrypt(encryptedPrivateKey, aesKey)
        var key = ECKey.fromPrivate(unencryptedPrivateKey)
        if (!isCompressed)
            key = key.decompress()
        if (!Arrays.equals(key.pubKey, pubKey))
            throw KeyCrypterException("Provided AES key is wrong")
        key.creationTimeSeconds = (creationTimeSeconds)
        return key
    }

    /**
     * Create a decrypted private key with AES key. Note that if the AES key is wrong, this
     * has some chance of throwing KeyCrypterException due to the corrupted padding that will result, but it can also
     * just yield a garbage key.
     *
     * @param aesKey The KeyParameter with the AES encryption key (usually constructed with keyCrypter#deriveKey and cached).
     */
    @Throws(KeyCrypterException::class)
    open fun decrypt(aesKey: KeyParameter): ECKey {
        val crypter = keyCrypter ?: throw KeyCrypterException("No key crypter available")
        return decrypt(crypter, aesKey)
    }

    /**
     * Creates decrypted private key if needed.
     */
    @Throws(KeyCrypterException::class)
    fun maybeDecrypt(aesKey: KeyParameter?): ECKey {
        return if (isEncrypted && aesKey != null) decrypt(aesKey) else this
    }

    /**
     * Indicates whether the private key is encrypted (true) or not (false).
     * A private key is deemed to be encrypted when there is both a KeyCrypter and the encryptedPrivateKey is non-zero.
     */
    override fun isEncrypted(): Boolean {
        return keyCrypter != null && encryptedPrivateKey != null && encryptedPrivateKey!!.encryptedBytes.size > 0
    }

    override fun getEncryptionType(): Protos.Wallet.EncryptionType? {
        return if (keyCrypter != null) keyCrypter!!.understoodEncryptionType else Protos.Wallet.EncryptionType.UNENCRYPTED
    }

    /**
     * A wrapper for [.getPrivKeyBytes] that returns null if the private key bytes are missing or would have
     * to be derived (for the HD key case).
     */
    override fun getSecretBytes(): ByteArray? {
        return if (hasPrivKey())
            privKeyBytes
        else
            null
    }

    /** An alias for [.getEncryptedPrivateKey]  */
    override fun getEncryptedData(): EncryptedData? {
        return encryptedPrivateKey
    }

    open class MissingPrivateKeyException : RuntimeException()

    class KeyIsEncryptedException : MissingPrivateKeyException()

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || o !is ECKey) return false
        val other = o as ECKey?
        return (Objects.equal(this.priv, other!!.priv)
                && Objects.equal(this.pub, other.pub)
                && Objects.equal(this.creationTimeSeconds, other.creationTimeSeconds)
                && Objects.equal(this.keyCrypter, other.keyCrypter)
                && Objects.equal(this.encryptedPrivateKey, other.encryptedPrivateKey))
    }

    override fun hashCode(): Int {
        // Public keys are random already so we can just use a part of them as the hashcode. Read from the start to
        // avoid picking up the type code (compressed vs uncompressed) which is tacked on the end.
        val bits = pubKey
        return Ints.fromBytes(bits[0], bits[1], bits[2], bits[3])
    }

    override fun toString(): String {
        return toString(false, null)
    }

    /**
     * Produce a string rendering of the ECKey INCLUDING the private key.
     * Unless you absolutely need the private key it is better for security reasons to just use [.toString].
     */
    fun toStringWithPrivate(params: NetworkParameters): String {
        return toString(true, params)
    }

    fun getPrivateKeyAsWiF(params: NetworkParameters?): String {
        return getPrivateKeyEncoded(params).toString()
    }

    private fun toString(includePrivate: Boolean, params: NetworkParameters?): String {
        val helper = MoreObjects.toStringHelper(this).omitNullValues()
        helper.add("pub HEX", publicKeyAsHex)
        if (includePrivate) {
            try {
                helper.add("priv HEX", privateKeyAsHex)
                helper.add("priv WIF", getPrivateKeyAsWiF(params))
            } catch (e: IllegalStateException) {
                // TODO: Make hasPrivKey() work for deterministic keys and fix this.
            } catch (e: Exception) {
                val message = e.message
                helper.add("priv EXCEPTION", e.javaClass.getName() + if (message != null) ": " + message else "")
            }

        }
        if (creationTimeSeconds > 0)
            helper.add("creationTimeSeconds", creationTimeSeconds)
        helper.add("keyCrypter", keyCrypter)
        if (includePrivate)
            helper.add("encryptedPrivateKey", encryptedPrivateKey)
        helper.add("isEncrypted", isEncrypted)
        helper.add("isPubKeyOnly", isPubKeyOnly)
        return helper.toString()
    }

    open fun formatKeyWithAddress(includePrivateKeys: Boolean, builder: StringBuilder, params: NetworkParameters) {
        val address = toAddress(params)
        builder.append("  addr:")
        builder.append(address.toString())
        builder.append("  hash160:")
        builder.append(Utils.HEX.encode(getPubKeyHash()))
        if (creationTimeSeconds > 0)
            builder.append("  creationTimeSeconds:").append(creationTimeSeconds)
        builder.append("\n")
        if (includePrivateKeys) {
            builder.append("  ")
            builder.append(toStringWithPrivate(params))
            builder.append("\n")
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(ECKey::class.java!!)

        /** Sorts oldest keys first, newest last.  */
        val AGE_COMPARATOR: Comparator<ECKey> = Comparator { k1, k2 ->
            if (k1.creationTimeSeconds == k2.creationTimeSeconds)
                0
            else
                if (k1.creationTimeSeconds > k2.creationTimeSeconds) 1 else -1
        }

        /** Compares pub key bytes using [com.google.common.primitives.UnsignedBytes.lexicographicalComparator]  */
        val PUBKEY_COMPARATOR: Comparator<ECKey> = object : Comparator<ECKey> {
            private val comparator = UnsignedBytes.lexicographicalComparator()

            override fun compare(k1: ECKey, k2: ECKey): Int {
                return comparator.compare(k1.pubKey, k2.pubKey)
            }
        }

        // The parameters of the secp256k1 curve that Bitcoin uses.
        private val CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1")

        /** The parameters of the secp256k1 curve that Bitcoin uses.  */
        val CURVE: ECDomainParameters

        /**
         * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a signature. If you aren't
         * sure what this is about, you can ignore it.
         */
        val HALF_CURVE_ORDER: BigInteger

        private val secureRandom: SecureRandom

        init {
            // Init proper random number generator, as some old Android installations have bugs that make it unsecure.
            if (Utils.isAndroidRuntime)
                LinuxSecureRandom()

            // Tell Bouncy Castle to precompute data that's needed during secp256k1 calculations. Increasing the width
            // number makes calculations faster, but at a cost of extra memory usage and with decreasing returns. 12 was
            // picked after consulting with the BC team.
            FixedPointUtil.precompute(CURVE_PARAMS.g, 12)
            CURVE = ECDomainParameters(CURVE_PARAMS.curve, CURVE_PARAMS.g, CURVE_PARAMS.n,
                    CURVE_PARAMS.h)
            HALF_CURVE_ORDER = CURVE_PARAMS.n.shiftRight(1)
            secureRandom = SecureRandom()
        }

        /**
         * Utility for compressing an elliptic curve point. Returns the same point if it's already compressed.
         * See the ECKey class docs for a discussion of point compression.
         */
        fun compressPoint(point: ECPoint): ECPoint {
            return getPointWithCompression(point, true)
        }

        fun compressPoint(point: LazyECPoint): LazyECPoint {
            return if (point.isCompressed) point else LazyECPoint(compressPoint(point.get()))
        }

        /**
         * Utility for decompressing an elliptic curve point. Returns the same point if it's already compressed.
         * See the ECKey class docs for a discussion of point compression.
         */
        fun decompressPoint(point: ECPoint): ECPoint {
            return getPointWithCompression(point, false)
        }

        fun decompressPoint(point: LazyECPoint): LazyECPoint {
            return if (!point.isCompressed) point else LazyECPoint(decompressPoint(point.get()))
        }

        private fun getPointWithCompression(point: ECPoint, compressed: Boolean): ECPoint {
            var point = point
            if (point.isCompressed == compressed)
                return point
            point = point.normalize()
            val x = point.affineXCoord.toBigInteger()
            val y = point.affineYCoord.toBigInteger()
            return CURVE.curve.createPoint(x, y, compressed)
        }

        /**
         * Construct an ECKey from an ASN.1 encoded private key. These are produced by OpenSSL and stored by Bitcoin
         * Core in its wallet. Note that this is slow because it requires an EC point multiply.
         */
        fun fromASN1(asn1privkey: ByteArray): ECKey {
            return extractKeyFromASN1(asn1privkey)
        }

        /**
         * Creates an ECKey given the private key only. The public key is calculated from it (this is slow), either
         * compressed or not.
         */
        @JvmOverloads
        fun fromPrivate(privKey: BigInteger, compressed: Boolean = true): ECKey {
            val point = publicPointFromPrivate(privKey)
            return ECKey(privKey, getPointWithCompression(point, compressed))
        }

        /**
         * Creates an ECKey given the private key only. The public key is calculated from it (this is slow). The resulting
         * public key is compressed.
         */
        fun fromPrivate(privKeyBytes: ByteArray): ECKey {
            return fromPrivate(BigInteger(1, privKeyBytes))
        }

        /**
         * Creates an ECKey given the private key only. The public key is calculated from it (this is slow), either
         * compressed or not.
         */
        fun fromPrivate(privKeyBytes: ByteArray, compressed: Boolean): ECKey {
            return fromPrivate(BigInteger(1, privKeyBytes), compressed)
        }

        /**
         * Creates an ECKey that simply trusts the caller to ensure that point is really the result of multiplying the
         * generator point by the private key. This is used to speed things up when you know you have the right values
         * already. The compression state of pub will be preserved.
         */
        fun fromPrivateAndPrecalculatedPublic(priv: BigInteger, pub: ECPoint): ECKey {
            return ECKey(priv, pub)
        }

        /**
         * Creates an ECKey that simply trusts the caller to ensure that point is really the result of multiplying the
         * generator point by the private key. This is used to speed things up when you know you have the right values
         * already. The compression state of the point will be preserved.
         */
        fun fromPrivateAndPrecalculatedPublic(priv: ByteArray, pub: ByteArray): ECKey {
            checkNotNull(priv)
            checkNotNull(pub)
            return ECKey(BigInteger(1, priv), CURVE.curve.decodePoint(pub))
        }

        /**
         * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given point. The
         * compression state of pub will be preserved.
         */
        fun fromPublicOnly(pub: ECPoint): ECKey {
            return ECKey(null, pub)
        }

        /**
         * Creates an ECKey that cannot be used for signing, only verifying signatures, from the given encoded point.
         * The compression state of pub will be preserved.
         */
        fun fromPublicOnly(pub: ByteArray): ECKey {
            return ECKey(null, CURVE.curve.decodePoint(pub))
        }

        /**
         * Constructs a key that has an encrypted private component. The given object wraps encrypted bytes and an
         * initialization vector. Note that the key will not be decrypted during this call: the returned ECKey is
         * unusable for signing unless a decryption key is supplied.
         */
        fun fromEncrypted(encryptedPrivateKey: EncryptedData, crypter: KeyCrypter, pubKey: ByteArray): ECKey {
            val key = fromPublicOnly(pubKey)
            key.encryptedPrivateKey = checkNotNull(encryptedPrivateKey)
            key.keyCrypter = checkNotNull(crypter)
            return key
        }

        /**
         * Returns public key bytes from the given private key. To convert a byte array into a BigInteger, use <tt>
         * new BigInteger(1, bytes);</tt>
         */
        fun publicKeyFromPrivate(privKey: BigInteger, compressed: Boolean): ByteArray {
            val point = publicPointFromPrivate(privKey)
            return point.getEncoded(compressed)
        }

        /**
         * Returns public key point from the given private key. To convert a byte array into a BigInteger, use <tt>
         * new BigInteger(1, bytes);</tt>
         */
        fun publicPointFromPrivate(privKey: BigInteger): ECPoint {
            var privKey = privKey
            /*
         * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than the group order,
         * but that could change in future versions.
         */
            if (privKey.bitLength() > CURVE.n.bitLength()) {
                privKey = privKey.mod(CURVE.n)
            }
            return FixedPointCombMultiplier().multiply(CURVE.g, privKey)
        }

        /**
         * If this global variable is set to true, sign() creates a dummy signature and verify() always returns true.
         * This is intended to help accelerate unit tests that do a lot of signing/verifying, which in the debugger
         * can be painfully slow.
         */
        @VisibleForTesting
        var FAKE_SIGNATURES = false

        /**
         *
         * Verifies the given ECDSA signature against the message bytes using the public key bytes.
         *
         *
         * When using native ECDSA verification, data must be 32 bytes, and no element may be
         * larger than 520 bytes.
         *
         * @param data      Hash of the data to verify.
         * @param signature ASN.1 encoded signature.
         * @param pub       The public key bytes to use.
         */
        fun verify(data: ByteArray, signature: ECDSASignature, pub: ByteArray): Boolean {
            if (FAKE_SIGNATURES)
                return true

            if (Secp256k1Context.isEnabled()) {
                try {
                    return NativeSecp256k1.verify(data, signature.encodeToDER(), pub)
                } catch (e: NativeSecp256k1Util.AssertFailException) {
                    log.error("Caught AssertFailException inside secp256k1", e)
                    return false
                }

            }

            val signer = ECDSASigner()
            val params = ECPublicKeyParameters(CURVE.curve.decodePoint(pub), CURVE)
            signer.init(false, params)
            try {
                return signer.verifySignature(data, signature.r, signature.s)
            } catch (e: NullPointerException) {
                // Bouncy Castle contains a bug that can cause NPEs given specially crafted signatures. Those signatures
                // are inherently invalid/attack sigs so we just fail them here rather than crash the thread.
                log.error("Caught NPE inside bouncy castle", e)
                return false
            }

        }

        /**
         * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
         *
         * @param data      Hash of the data to verify.
         * @param signature ASN.1 encoded signature.
         * @param pub       The public key bytes to use.
         */
        fun verify(data: ByteArray, signature: ByteArray, pub: ByteArray): Boolean {
            if (Secp256k1Context.isEnabled()) {
                try {
                    return NativeSecp256k1.verify(data, signature, pub)
                } catch (e: NativeSecp256k1Util.AssertFailException) {
                    log.error("Caught AssertFailException inside secp256k1", e)
                    return false
                }

            }
            return verify(data, ECDSASignature.decodeFromDER(signature), pub)
        }

        /**
         * Returns true if the given pubkey is canonical, i.e. the correct length taking into account compression.
         */
        fun isPubKeyCanonical(pubkey: ByteArray): Boolean {
            if (pubkey.size < 33)
                return false
            if (pubkey[0].toInt() == 0x04) {
                // Uncompressed pubkey
                if (pubkey.size != 65)
                    return false
            } else if (pubkey[0].toInt() == 0x02 || pubkey[0].toInt() == 0x03) {
                // Compressed pubkey
                if (pubkey.size != 33)
                    return false
            } else
                return false
            return true
        }

        private fun extractKeyFromASN1(asn1privkey: ByteArray): ECKey {
            // To understand this code, see the definition of the ASN.1 format for EC private keys in the OpenSSL source
            // code in ec_asn1.c:
            //
            // ASN1_SEQUENCE(EC_PRIVATEKEY) = {
            //   ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
            //   ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
            //   ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
            // } ASN1_SEQUENCE_END(EC_PRIVATEKEY)
            //
            try {
                val decoder = ASN1InputStream(asn1privkey)
                val seq = decoder.readObject() as DLSequence
                checkArgument(decoder.readObject() == null, "Input contains extra bytes")
                decoder.close()

                checkArgument(seq.size() == 4, "Input does not appear to be an ASN.1 OpenSSL EC private key")

                checkArgument((seq.getObjectAt(0) as ASN1Integer).value == BigInteger.ONE,
                        "Input is of wrong version")

                val privbits = (seq.getObjectAt(1) as ASN1OctetString).octets
                val privkey = BigInteger(1, privbits)

                val pubkey = seq.getObjectAt(3) as ASN1TaggedObject
                checkArgument(pubkey.tagNo == 1, "Input has 'publicKey' with bad tag number")
                val pubbits = (pubkey.`object` as DERBitString).bytes
                checkArgument(pubbits.size == 33 || pubbits.size == 65, "Input has 'publicKey' with invalid length")
                val encoding = pubbits[0] and 0xFF.toByte()
                // Only allow compressed(2,3) and uncompressed(4), not infinity(0) or hybrid(6,7)
                checkArgument(encoding >= 2 && encoding <= 4, "Input has 'publicKey' with invalid encoding")

                // Now sanity check to ensure the pubkey bytes match the privkey.
                val compressed = pubbits.size == 33
                val key = ECKey(privkey, null, compressed)
                if (!Arrays.equals(key.pubKey, pubbits))
                    throw IllegalArgumentException("Public key in ASN.1 structure does not match private key.")
                return key
            } catch (e: IOException) {
                throw RuntimeException(e)  // Cannot happen, reading from memory stream.
            }

        }

        /**
         * Given an arbitrary piece of text and a Bitcoin-format message signature encoded in base64, returns an ECKey
         * containing the public key that was used to sign it. This can then be compared to the expected public key to
         * determine if the signature was correct. These sorts of signatures are compatible with the Bitcoin-Qt/bitcoind
         * format generated by signmessage/verifymessage RPCs and GUI menu options. They are intended for humans to verify
         * their communications with each other, hence the base64 format and the fact that the input is text.
         *
         * @param message Some piece of human readable text.
         * @param signatureBase64 The Bitcoin-format message signature in base64
         * @throws SignatureException If the public key could not be recovered or if there was a signature format error.
         */
        @Throws(SignatureException::class)
        fun signedMessageToKey(message: String, signatureBase64: String): ECKey {
            val signatureEncoded: ByteArray
            try {
                signatureEncoded = Base64.decode(signatureBase64)
            } catch (e: RuntimeException) {
                // This is what you get back from Bouncy Castle if base64 doesn't decode :(
                throw SignatureException("Could not decode base64", e)
            }

            // Parse the signature bytes into r/s and the selector value.
            if (signatureEncoded.size < 65)
                throw SignatureException("Signature truncated, expected 65 bytes and got " + signatureEncoded.size)
            var header = signatureEncoded[0] and 0xFF.toByte()
            // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
            //                  0x1D = second key with even y, 0x1E = second key with odd y
            if (header < 27 || header > 34)
                throw SignatureException("Header byte out of range: " + header)
            val r = BigInteger(1, Arrays.copyOfRange(signatureEncoded, 1, 33))
            val s = BigInteger(1, Arrays.copyOfRange(signatureEncoded, 33, 65))
            val sig = ECDSASignature(r, s)
            val messageBytes = Utils.formatMessageForSigning(message)
            // Note that the C++ code doesn't actually seem to specify any character encoding. Presumably it's whatever
            // JSON-SPIRIT hands back. Assume UTF-8 for now.
            val messageHash = Sha256Hash.twiceOf(messageBytes)
            var compressed = false
            if (header >= 31) {
                compressed = true
                header = (header.toInt() - 4).toByte()
            }
            val recId = header - 27
            return recoverFromSignature(recId, sig, messageHash, compressed) ?: throw SignatureException("Could not recover public key from signature")
        }

        /**
         *
         * Given the components of a signature and a selector value, recover and return the public key
         * that generated the signature according to the algorithm in SEC1v2 section 4.1.6.
         *
         *
         * The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the correct one. Because
         * the key recovery operation yields multiple potential keys, the correct key must either be stored alongside the
         * signature, or you must be willing to try each recId in turn until you find one that outputs the key you are
         * expecting.
         *
         *
         * If this method returns null it means recovery was not possible and recId should be iterated.
         *
         *
         * Given the above two points, a correct usage of this method is inside a for loop from 0 to 3, and if the
         * output is null OR a key that is not the one you expect, you try again with the next recId.
         *
         * @param recId Which possible key to recover.
         * @param sig the R and S components of the signature, wrapped.
         * @param message Hash of the data that was signed.
         * @param compressed Whether or not the original pubkey was compressed.
         * @return An ECKey containing only the public part, or null if recovery wasn't possible.
         */
        fun recoverFromSignature(recId: Int, sig: ECDSASignature, message: Sha256Hash, compressed: Boolean): ECKey? {
            Preconditions.checkArgument(recId >= 0, "recId must be positive")
            Preconditions.checkArgument(sig.r.signum() >= 0, "r must be positive")
            Preconditions.checkArgument(sig.s.signum() >= 0, "s must be positive")
            Preconditions.checkNotNull(message)
            // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
            //   1.1 Let x = r + jn
            val n = CURVE.n  // Curve order.
            val i = BigInteger.valueOf(recId.toLong() / 2)
            val x = sig.r.add(i.multiply(n))
            //   1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
            //        specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
            //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
            //        conversion routine specified in Section 2.3.4. If this conversion routine outputs “invalid”, then
            //        do another iteration of Step 1.
            //
            // More concisely, what these points mean is to use X as a compressed public key.
            val prime = SecP256K1Curve.q
            if (x.compareTo(prime) >= 0) {
                // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
                return null
            }
            // Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
            // So it's encoded in the recId.
            val R = decompressKey(x, recId and 1 == 1)
            //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers responsibility).
            if (!R.multiply(n).isInfinity)
                return null
            //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
            val e = message.toBigInteger()
            //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
            //   1.6.1. Compute a candidate public key as:
            //               Q = mi(r) * (sR - eG)
            //
            // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
            //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
            // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n). In the above equation
            // ** is point multiplication and + is point addition (the EC group operator).
            //
            // We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
            // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
            val eInv = BigInteger.ZERO.subtract(e).mod(n)
            val rInv = sig.r.modInverse(n)
            val srInv = rInv.multiply(sig.s).mod(n)
            val eInvrInv = rInv.multiply(eInv).mod(n)
            val q = ECAlgorithms.sumOfTwoMultiplies(CURVE.g, eInvrInv, R, srInv)
            return ECKey.fromPublicOnly(q.getEncoded(compressed))
        }

        /** Decompress a compressed public key (x co-ord and low-bit of y-coord).  */
        private fun decompressKey(xBN: BigInteger, yBit: Boolean): ECPoint {
            val x9 = X9IntegerConverter()
            val compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.curve))
            compEnc[0] = (if (yBit) 0x03 else 0x02).toByte()
            return CURVE.curve.decodePoint(compEnc)
        }

        /**
         *
         * Check that it is possible to decrypt the key with the keyCrypter and that the original key is returned.
         *
         *
         * Because it is a critical failure if the private keys cannot be decrypted successfully (resulting of loss of all
         * bitcoins controlled by the private key) you can use this method to check when you *encrypt* a wallet that
         * it can definitely be decrypted successfully.
         *
         *
         * See [Wallet.encrypt] for example usage.
         *
         * @return true if the encrypted key can be decrypted back to the original key successfully.
         */
        fun encryptionIsReversible(originalKey: ECKey, encryptedKey: ECKey, keyCrypter: KeyCrypter, aesKey: KeyParameter): Boolean {
            try {
                val rebornUnencryptedKey = encryptedKey.decrypt(keyCrypter, aesKey)
                val originalPrivateKeyBytes = originalKey.privKeyBytes
                val rebornKeyBytes = rebornUnencryptedKey.privKeyBytes
                if (!Arrays.equals(originalPrivateKeyBytes, rebornKeyBytes)) {
                    log.error("The check that encryption could be reversed failed for {}", originalKey)
                    return false
                }
                return true
            } catch (kce: KeyCrypterException) {
                log.error(kce.message)
                return false
            }

        }
    }
}
/**
 * Generates an entirely new keypair. Point compression is used so the resulting public key will be 33 bytes
 * (32 for the co-ordinate and 1 byte to represent the y bit).
 */
/**
 * Creates an ECKey given the private key only. The public key is calculated from it (this is slow). The resulting
 * public key is compressed.
 */
/**
 * Signs a text message using the standard Bitcoin messaging signing format and returns the signature as a base64
 * encoded string.
 *
 * @throws IllegalStateException if this ECKey does not have the private part.
 * @throws KeyCrypterException if this ECKey is encrypted and no AESKey is provided or it does not decrypt the ECKey.
 */
