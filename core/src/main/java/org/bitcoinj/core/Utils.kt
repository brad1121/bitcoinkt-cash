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

import com.google.common.base.Charsets
import com.google.common.base.Joiner
import com.google.common.collect.Lists
import com.google.common.collect.Ordering
import com.google.common.io.BaseEncoding
import com.google.common.io.Resources
import com.google.common.primitives.Ints
import com.google.common.primitives.UnsignedLongs
import org.spongycastle.crypto.digests.RIPEMD160Digest

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.UnsupportedEncodingException
import java.math.BigInteger
import java.net.URL
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.TimeUnit

import com.google.common.base.Preconditions.checkArgument
import com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly
import java.nio.charset.Charset
import kotlin.experimental.and
import kotlin.experimental.or

/**
 * A collection of various utility methods that are helpful for working with the Bitcoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
object Utils {

    /** The string that prefixes all text messages signed using Bitcoin keys.  */
    val BITCOIN_SIGNED_MESSAGE_HEADER = "Bitcoin Signed Message:\n"
    val BITCOIN_SIGNED_MESSAGE_HEADER_BYTES = BITCOIN_SIGNED_MESSAGE_HEADER.toByteArray(Charsets.UTF_8)

    private val SPACE_JOINER = Joiner.on(" ")

    private var mockSleepQueue: BlockingQueue<Boolean>? = null

    /**
     * Hex encoding used throughout the framework. Use with HEX.encode(byte[]) or HEX.decode(CharSequence).
     */
    val HEX = BaseEncoding.base16().lowerCase()

    /**
     * If non-null, overrides the return value of now().
     */
    @Volatile
    var mockTime: Date? = null

    private val UTC = TimeZone.getTimeZone("UTC")

    val isWindows: Boolean
        get() = System.getProperty("os.name").toLowerCase().contains("win")

    // 00000001, 00000010, 00000100, 00001000, ...
    private val bitMask = intArrayOf(0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

    private var isAndroid = -1
    val isAndroidRuntime: Boolean
        get() {
            if (isAndroid == -1) {
                val runtime = System.getProperty("java.runtime.name")
                isAndroid = if (runtime != null && runtime == "Android Runtime") 1 else 0
            }
            return isAndroid == 1
        }

    internal var ForkBlockTime: Long = 1501593374 // 6 blocks after the fork time

    /**
     * The regular [java.math.BigInteger.toByteArray] method isn't quite what we often need: it appends a
     * leading zero to indicate that the number is positive and may need padding.
     *
     * @param b the integer to format into a byte array
     * @param numBytes the desired size of the resulting byte array
     * @return numBytes byte long array.
     */
    fun bigIntegerToBytes(b: BigInteger?, numBytes: Int): ByteArray? {
        if (b == null) {
            return null
        }
        val bytes = ByteArray(numBytes)
        val biBytes = b.toByteArray()
        val start = if (biBytes.size == numBytes + 1) 1 else 0
        val length = Math.min(biBytes.size, numBytes)
        System.arraycopy(biBytes, start, bytes, numBytes - length, length)
        return bytes
    }
//*_*CHECK -- ALl of this needs review
    fun uint32ToByteArrayBE(`val`: Long, out: ByteArray, offset: Int) {
        out[offset] = (0xFF and (`val` shr 24).toInt()).toByte()
        out[offset + 1] = (0xFF and (`val` shr 16).toInt()).toByte()
        out[offset + 2] = (0xFF and (`val` shr 8).toInt()).toByte()
        out[offset + 3] = (0xFF and `val`.toInt()).toByte()
    }

    fun uint32ToByteArrayLE(`val`: Long, out: ByteArray, offset: Int) {
        out[offset] = (0xFF and `val`.toInt()).toByte()
        out[offset + 1] = (0xFF and (`val` shr 8).toInt()).toByte()
        out[offset + 2] = (0xFF and (`val` shr 16).toInt()).toByte()
        out[offset + 3] = (0xFF and (`val` shr 24).toInt()).toByte()
    }

    fun uint64ToByteArrayLE(`val`: Long, out: ByteArray, offset: Int) {
        out[offset] = (0xFF and `val`.toInt()).toByte()
        out[offset + 1] = (0xFF and (`val` shr 8).toInt()).toByte()
        out[offset + 2] = (0xFF and (`val` shr 16).toInt()).toByte()
        out[offset + 3] = (0xFF and (`val` shr 24).toInt()).toByte()
        out[offset + 4] = (0xFF and (`val` shr 32).toInt()).toByte()
        out[offset + 5] = (0xFF and (`val` shr 40).toInt()).toByte()
        out[offset + 6] = (0xFF and (`val` shr 48).toInt()).toByte()
        out[offset + 7] = (0xFF and (`val` shr 56).toInt()).toByte()
    }

    @Throws(IOException::class)
    fun uint32ToByteStreamLE(`val`: Long, stream: OutputStream) {
        stream.write((0xFF and `val`.toInt()).toInt())
        stream.write((0xFF and (`val` shr 8).toInt()).toInt())
        stream.write((0xFF and (`val` shr 16).toInt()).toInt())
        stream.write((0xFF and (`val` shr 24).toInt()).toInt())
    }

    @Throws(IOException::class)
    fun int64ToByteStreamLE(`val`: Long, stream: OutputStream) {
        stream.write((0xFF and `val`.toInt()).toInt())
        stream.write((0xFF and (`val` shr 8).toInt()).toInt())
        stream.write((0xFF and (`val` shr 16).toInt()).toInt())
        stream.write((0xFF and (`val` shr 24).toInt()).toInt())
        stream.write((0xFF and (`val` shr 32).toInt()).toInt())
        stream.write((0xFF and (`val` shr 40).toInt()).toInt())
        stream.write((0xFF and (`val` shr 48).toInt()).toInt())
        stream.write((0xFF and (`val` shr 56).toInt()).toInt())
    }

    @Throws(IOException::class)
    fun uint64ToByteStreamLE(`val`: BigInteger, stream: OutputStream) {
        var bytes = `val`.toByteArray()
        if (bytes.size > 8) {
            throw RuntimeException("Input too large to encode into a uint64")
        }
        bytes = reverseBytes(bytes)
        stream.write(bytes)
        if (bytes.size < 8) {
            for (i in 0 until 8 - bytes.size)
                stream.write(0)
        }
    }

    /**
     * Work around lack of unsigned types in Java.
     */
    fun isLessThanUnsigned(n1: Long, n2: Long): Boolean {
        return UnsignedLongs.compare(n1, n2) < 0
    }

    /**
     * Work around lack of unsigned types in Java.
     */
    fun isLessThanOrEqualToUnsigned(n1: Long, n2: Long): Boolean {
        return UnsignedLongs.compare(n1, n2) <= 0
    }

    /**
     * Returns a copy of the given byte array in reverse order.
     */
    fun reverseBytes(bytes: ByteArray): ByteArray {
        // We could use the XOR trick here but it's easier to understand if we don't. If we find this is really a
        // performance issue the matter can be revisited.
        val buf = ByteArray(bytes.size)
        for (i in bytes.indices)
            buf[i] = bytes[bytes.size - 1 - i]
        return buf
    }

    /**
     * Returns a copy of the given byte array with the bytes of each double-word (4 bytes) reversed.
     *
     * @param bytes length must be divisible by 4.
     * @param trimLength trim output to this length.  If positive, must be divisible by 4.
     */
    fun reverseDwordBytes(bytes: ByteArray, trimLength: Int): ByteArray {
        checkArgument(bytes.size % 4 == 0)
        checkArgument(trimLength < 0 || trimLength % 4 == 0)

        val rev = ByteArray(if (trimLength >= 0 && bytes.size > trimLength) trimLength else bytes.size)

        var i = 0
        while (i < rev.size) {
            System.arraycopy(bytes, i, rev, i, 4)
            for (j in 0..3) {
                rev[i + j] = bytes[i + 3 - j]
            }
            i += 4
        }
        return rev
    }

    /** Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in little endian format.  */
    fun readUint32(bytes: ByteArray, offset: Int): Long {
        return  bytes[offset].toLong() and 0xffL or
                bytes[offset + 1].toLong() and ( 0xffL shl 8 )or
                bytes[offset + 2].toLong() and ( 0xffL shl 16) or
                bytes[offset + 3].toLong() and ( 0xffL shl 24)
    }

    /** Parse 8 bytes from the byte array (starting at the offset) as signed 64-bit integer in little endian format.  */
    fun readInt64(bytes: ByteArray, offset: Int): Long {
        return   bytes[offset].toLong() and 0xffL or
                bytes[offset + 1].toLong() and 0xffL shl 8 or
                bytes[offset + 2].toLong() and 0xffL shl 16 or
                bytes[offset + 3].toLong() and 0xffL shl 24 or
                bytes[offset + 4].toLong() and 0xffL shl 32 or
                bytes[offset + 5].toLong() and 0xffL shl 40 or
                bytes[offset + 6].toLong() and 0xffL shl 48 or
                bytes[offset + 7].toLong() and 0xffL shl 56
    }

    /** Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in big endian format.  */
    fun readUint32BE(bytes: ByteArray, offset: Int): Long {
        return bytes[offset].toLong() and 0xffL shl 24 or
                (bytes[offset + 1].toLong() and 0xffL shl 16) or
                (bytes[offset + 2].toLong() and 0xffL shl 8) or
                (bytes[offset + 3].toLong() and 0xffL)
    }

    /** Parse 2 bytes from the byte array (starting at the offset) as unsigned 16-bit integer in big endian format.  */
    fun readUint16BE(bytes: ByteArray, offset: Int): Int {
        return bytes[offset].toInt() and 0xff shl 8 or (bytes[offset + 1].toInt() and 0xff)
    }

    /**
     * Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
     */
    fun sha256hash160(input: ByteArray): ByteArray {
        val sha256 = Sha256Hash.hash(input)
        val digest = RIPEMD160Digest()
        digest.update(sha256, 0, sha256.size)
        val out = ByteArray(20)
        digest.doFinal(out, 0)
        return out
    }

    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     * @param hasLength can be set to false if the given array is missing the 4 byte length field
     */
    fun decodeMPI(mpi: ByteArray, hasLength: Boolean): BigInteger {
        val buf: ByteArray
        if (hasLength) {
            val length = readUint32BE(mpi, 0).toInt()
            buf = ByteArray(length)
            System.arraycopy(mpi, 4, buf, 0, length)
        } else
            buf = mpi
        if (buf.size == 0)
            return BigInteger.ZERO
        val isNegative = buf[0].toInt() and 0x80 == 0x80
        if (isNegative)
            buf[0] = buf[0] and 0x7f
        val result = BigInteger(buf)
        return if (isNegative) result.negate() else result
    }

    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     * @param includeLength indicates whether the 4 byte length field should be included
     */
    fun encodeMPI(value: BigInteger, includeLength: Boolean): ByteArray {
        var value = value
        if (value == BigInteger.ZERO) {
            return if (!includeLength)
                byteArrayOf()
            else
                byteArrayOf(0x00, 0x00, 0x00, 0x00)
        }
        val isNegative = value.signum() < 0
        if (isNegative)
            value = value.negate()
        val array = value.toByteArray()
        var length = array.size
        if (array[0].toInt() and 0x80 == 0x80)
            length++
        if (includeLength) {
            val result = ByteArray(length + 4)
            System.arraycopy(array, 0, result, length - array.size + 3, array.size)
            uint32ToByteArrayBE(length.toLong(), result, 0)
            if (isNegative)
                result[4] = result[4] or 0x80.toByte()
            return result
        } else {
            val result: ByteArray
            if (length != array.size) {
                result = ByteArray(length)
                System.arraycopy(array, 0, result, 1, array.size)
            } else
                result = array
            if (isNegative)
                result[0] = result[0] or 0x80.toByte()
            return result
        }
    }

    /**
     *
     * The "compact" format is a representation of a whole number N using an unsigned 32 bit number similar to a
     * floating point format. The most significant 8 bits are the unsigned exponent of base 256. This exponent can
     * be thought of as "number of bytes of N". The lower 23 bits are the mantissa. Bit number 24 (0x800000) represents
     * the sign of N. Therefore, N = (-1^sign) * mantissa * 256^(exponent-3).
     *
     *
     * Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn(). MPI uses the most significant bit of the
     * first byte as sign. Thus 0x1234560000 is compact 0x05123456 and 0xc0de000000 is compact 0x0600c0de. Compact
     * 0x05c0de00 would be -0x40de000000.
     *
     *
     * Bitcoin only uses this "compact" format for encoding difficulty targets, which are unsigned 256bit quantities.
     * Thus, all the complexities of the sign bit and using base 256 are probably an implementation accident.
     */
    fun decodeCompactBits(compact: Long): BigInteger {
        val size = (compact shr 24).toInt() and 0xFF
        val bytes = ByteArray(4 + size)
        bytes[3] = size.toByte()
        if (size >= 1) bytes[4] = (compact shr 16 and 0xFF).toByte()
        if (size >= 2) bytes[5] = (compact shr 8 and 0xFF).toByte()
        if (size >= 3) bytes[6] = (compact and 0xFF).toByte()
        return decodeMPI(bytes, true)
    }

    /**
     * @see Utils.decodeCompactBits
     */
    fun encodeCompactBits(value: BigInteger): Long {
        var result: Long
        var size = value.toByteArray().size
        if (size <= 3)
            result = value.toLong() shl 8 * (3 - size)
        else
            result = value.shiftRight(8 * (size - 3)).toLong()
        // The 0x00800000 bit denotes the sign.
        // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
        if (result and 0x00800000L != 0L) {
            result = result shr 8
            size++
        }
        result = result or (size shl 24).toLong()
        result = result or (if (value.signum() == -1) 0x00800000 else 0).toLong()
        return result
    }

    /**
     * Advances (or rewinds) the mock clock by the given number of seconds.
     */
    fun rollMockClock(seconds: Int): Date? {
        return rollMockClockMillis((seconds * 1000).toLong())
    }

    /**
     * Advances (or rewinds) the mock clock by the given number of milliseconds.
     */
    fun rollMockClockMillis(millis: Long): Date? {
        if (mockTime == null)
            throw IllegalStateException("You need to use setMockClock() first.")
        mockTime = Date(mockTime!!.time + millis)
        return mockTime
    }

    /**
     * Sets the mock clock to the current time.
     */
    fun setMockClock() {
        mockTime = Date()
    }

    /**
     * Sets the mock clock to the given time (in seconds).
     */
    fun setMockClock(mockClockSeconds: Long) {
        mockTime = Date(mockClockSeconds * 1000)
    }

    /**
     * Returns the current time, or a mocked out equivalent.
     */
    fun now(): Date? {
        return if (mockTime != null) mockTime else Date()
    }

    // TODO: Replace usages of this where the result is / 1000 with currentTimeSeconds.
    /** Returns the current time in milliseconds since the epoch, or a mocked out equivalent.  */
    fun currentTimeMillis(): Long {
        return if (mockTime != null) mockTime!!.time else System.currentTimeMillis()
    }

    fun currentTimeSeconds(): Long {
        return currentTimeMillis() / 1000
    }

    /**
     * Formats a given date+time value to an ISO 8601 string.
     * @param dateTime value to format, as a Date
     */
    fun dateTimeFormat(dateTime: Date): String {
        val iso8601 = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        iso8601.timeZone = UTC
        return iso8601.format(dateTime)
    }

    /**
     * Formats a given date+time value to an ISO 8601 string.
     * @param dateTime value to format, unix time (ms)
     */
    fun dateTimeFormat(dateTime: Long): String {
        val iso8601 = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        iso8601.timeZone = UTC
        return iso8601.format(dateTime)
    }

    /**
     * Returns a string containing the string representation of the given items,
     * delimited by a single space character.
     *
     * @param items the items to join
     * @param <T> the item type
     * @return the joined space-delimited string
    </T> */
    fun <T> join(items: Iterable<T>): String {
        return SPACE_JOINER.join(items)
    }

    fun copyOf(`in`: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        System.arraycopy(`in`, 0, out, 0, Math.min(length, `in`.size))
        return out
    }

    /**
     * Creates a copy of bytes and appends b to the end of it
     */
    fun appendByte(bytes: ByteArray, b: Byte): ByteArray {
        val result = Arrays.copyOf(bytes, bytes.size + 1)
        result[result.size - 1] = b
        return result
    }

    /**
     * Constructs a new String by decoding the given bytes using the specified charset.
     *
     *
     * This is a convenience method which wraps the checked exception with a RuntimeException.
     * The exception can never occur given the charsets
     * US-ASCII, ISO-8859-1, UTF-8, UTF-16, UTF-16LE or UTF-16BE.
     *
     * @param bytes the bytes to be decoded into characters
     * @param charsetName the name of a supported [charset][java.nio.charset.Charset]
     * @return the decoded String
     */
    fun toString(bytes: ByteArray, charsetName: String): String {
        try {
            return String(bytes, charsetName as Charset)
        } catch (e: UnsupportedEncodingException) {
            throw RuntimeException(e)
        }

    }

    /**
     * Encodes the given string into a sequence of bytes using the named charset.
     *
     *
     * This is a convenience method which wraps the checked exception with a RuntimeException.
     * The exception can never occur given the charsets
     * US-ASCII, ISO-8859-1, UTF-8, UTF-16, UTF-16LE or UTF-16BE.
     *
     * @param str the string to encode into bytes
     * @param charsetName the name of a supported [charset][java.nio.charset.Charset]
     * @return the encoded bytes
     */
    fun toBytes(str: CharSequence, charsetName: String): ByteArray {
        try {
            return str.toString().toByteArray(charset(charsetName))
        } catch (e: UnsupportedEncodingException) {
            throw RuntimeException(e)
        }

    }

    /**
     * Attempts to parse the given string as arbitrary-length hex or base58 and then return the results, or null if
     * neither parse was successful.
     */
    fun parseAsHexOrBase58(data: String): ByteArray? {
        try {
            return HEX.decode(data)
        } catch (e: Exception) {
            // Didn't decode as hex, try base58.
            try {
                return Base58.decodeChecked(data)
            } catch (e1: AddressFormatException) {
                return null
            }

        }

    }

    /**
     *
     * Given a textual message, returns a byte buffer formatted as follows:
     *
     * <tt>
     *
     *[24] "Bitcoin Signed Message:\n" [message.length as a varint] message</tt>
     */
    fun formatMessageForSigning(message: String): ByteArray {
        try {
            val bos = ByteArrayOutputStream()
            bos.write(BITCOIN_SIGNED_MESSAGE_HEADER_BYTES.size)
            bos.write(BITCOIN_SIGNED_MESSAGE_HEADER_BYTES)
            val messageBytes = message.toByteArray(Charsets.UTF_8)
            val size = VarInt(messageBytes.size.toLong())
            bos.write(size.encode())
            bos.write(messageBytes)
            return bos.toByteArray()
        } catch (e: IOException) {
            throw RuntimeException(e)  // Cannot happen.
        }

    }

    /** Checks if the given bit is set in data, using little endian (not the same as Java native big endian)  */
    fun checkBitLE(data: ByteArray, index: Int): Boolean {
        return data[index.ushr(3)].toInt() and bitMask[7 and index] != 0
    }

    /** Sets the given bit in data to one, using little endian (not the same as Java native big endian)  */
    fun setBitLE(data: ByteArray, index: Int) {
        data[index.ushr(3)] = data[index.ushr(3)] or bitMask[7 and index].toByte()
    }

    /** Sleep for a span of time, or mock sleep if enabled  */
    fun sleep(millis: Long) {
        if (mockSleepQueue == null) {
            sleepUninterruptibly(millis, TimeUnit.MILLISECONDS)
        } else {
            try {
                val isMultiPass = mockSleepQueue!!.take()
                rollMockClockMillis(millis)
                if (isMultiPass)
                    mockSleepQueue!!.offer(true)
            } catch (e: InterruptedException) {
                // Ignored.
            }

        }
    }

    /** Enable or disable mock sleep.  If enabled, set mock time to current time.  */
    fun setMockSleep(isEnable: Boolean) {
        if (isEnable) {
            mockSleepQueue = ArrayBlockingQueue(1)
            mockTime = Date(System.currentTimeMillis())
        } else {
            mockSleepQueue = null
        }
    }

    /** Let sleeping thread pass the synchronization point.   */
    fun passMockSleep() {
        mockSleepQueue!!.offer(false)
    }

    /** Let the sleeping thread pass the synchronization point any number of times.  */
    fun finishMockSleep() {
        if (mockSleepQueue != null) {
            mockSleepQueue!!.offer(true)
        }
    }

    private class Pair(internal var item: Int, internal var count: Int) : Comparable<Pair> {
        // note that in this implementation compareTo() is not consistent with equals()
        override fun compareTo(o: Pair): Int {
            return -Ints.compare(count, o.count)
        }
    }

    fun maxOfMostFreq(vararg items: Int): Int {
        // Java 6 sucks.
        val list = ArrayList<Int>(items.size)
        for (item in items) list.add(item)
        return maxOfMostFreq(list)
    }

    fun maxOfMostFreq(items: List<Int>): Int {
        var items = items
        if (items.isEmpty())
            return 0
        // This would be much easier in a functional language (or in Java 8).
        items = Ordering.natural<Comparable>().reverse<Comparable>().sortedCopy(items)
        val pairs = Lists.newLinkedList<Pair>()
        pairs.add(Pair(items[0], 0))
        for (item in items) {
            var pair = pairs.last
            if (pair.item != item)
                pairs.add(pair = Utils.Pair(item, 0))
            pair.count++
        }
        // pairs now contains a uniqified list of the sorted inputs, with counts for how often that item appeared.
        // Now sort by how frequently they occur, and pick the max of the most frequent.
        Collections.sort(pairs)
        val maxCount = pairs.first.count
        var maxItem = pairs.first.item
        for (pair in pairs) {
            if (pair.count != maxCount)
                break
            maxItem = Math.max(maxItem, pair.item)
        }
        return maxItem
    }

    /**
     * Reads and joins together with LF char (\n) all the lines from given file. It's assumed that file is in UTF-8.
     */
    @Throws(IOException::class)
    fun getResourceAsString(url: URL): String {
        val lines = Resources.readLines(url, Charsets.UTF_8)
        return Joiner.on('\n').join(lines)
    }

    // Can't use Closeable here because it's Java 7 only and Android devices only got that with KitKat.
    fun closeUnchecked(stream: InputStream): InputStream {
        try {
            stream.close()
            return stream
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

    fun closeUnchecked(stream: OutputStream): OutputStream {
        try {
            stream.close()
            return stream
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

    fun isAfterFork(time: Long): Boolean {
        return time >= ForkBlockTime
    }
}
