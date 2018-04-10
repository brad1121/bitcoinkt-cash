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

/**
 * A variable-length encoded unsigned integer using Satoshi's encoding (a.k.a. "CompactSize").
 */
class VarInt {
    val value: Long
    /**
     * Returns the original number of bytes used to encode the value if it was
     * deserialized from a byte array, or the minimum encoded size if it was not.
     */
    val originalSizeInBytes: Int

    /**
     * Returns the minimum encoded size of the value.
     */
    val sizeInBytes: Int
        get() = sizeOf(value)

    /**
     * Constructs a new VarInt with the given unsigned long value.
     *
     * @param value the unsigned long value (beware widening conversion of negatives!)
     */
    constructor(value: Long) {
        this.value = value
        originalSizeInBytes = sizeInBytes
    }

    /**
     * Constructs a new VarInt with the value parsed from the specified offset of the given buffer.
     *
     * @param buf the buffer containing the value
     * @param offset the offset of the value
     */
    constructor(buf: ByteArray, offset: Int) {
        val first = 0xFF and buf[offset]
        if (first < 253) {
            value = first.toLong()
            originalSizeInBytes = 1 // 1 data byte (8 bits)
        } else if (first == 253) {
            value = (0xFF and buf[offset + 1] or (0xFF and buf[offset + 2] shl 8)).toLong()
            originalSizeInBytes = 3 // 1 marker + 2 data bytes (16 bits)
        } else if (first == 254) {
            value = Utils.readUint32(buf, offset + 1)
            originalSizeInBytes = 5 // 1 marker + 4 data bytes (32 bits)
        } else {
            value = Utils.readInt64(buf, offset + 1)
            originalSizeInBytes = 9 // 1 marker + 8 data bytes (64 bits)
        }
    }

    /**
     * Encodes the value into its minimal representation.
     *
     * @return the minimal encoded bytes of the value
     */
    fun encode(): ByteArray {
        val bytes: ByteArray
        when (sizeOf(value)) {
            1 -> return byteArrayOf(value.toByte())
            3 -> return byteArrayOf(253.toByte(), value.toByte(), (value shr 8).toByte())
            5 -> {
                bytes = ByteArray(5)
                bytes[0] = 254.toByte()
                Utils.uint32ToByteArrayLE(value, bytes, 1)
                return bytes
            }
            else -> {
                bytes = ByteArray(9)
                bytes[0] = 255.toByte()
                Utils.uint64ToByteArrayLE(value, bytes, 1)
                return bytes
            }
        }
    }

    companion object {

        /**
         * Returns the minimum encoded size of the given unsigned long value.
         *
         * @param value the unsigned long value (beware widening conversion of negatives!)
         */
        fun sizeOf(value: Long): Int {
            // if negative, it's actually a very large unsigned long value
            if (value < 0) return 9 // 1 marker + 8 data bytes
            if (value < 253) return 1 // 1 data byte
            if (value <= 0xFFFFL) return 3 // 1 marker + 2 data bytes
            return if (value <= 0xFFFFFFFFL) 5 else 9 // 1 marker + 4 data bytes
// 1 marker + 8 data bytes
        }
    }
}
