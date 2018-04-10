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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream

/**
 * An unsynchronized implementation of ByteArrayOutputStream that will return the backing byte array if its length == size().
 * This avoids unneeded array copy where the BOS is simply being used to extract a byte array of known length from a
 * 'serialized to stream' method.
 *
 *
 * Unless the final length can be accurately predicted the only performance this will yield is due to unsynchronized
 * methods.
 *
 * @author git
 */
class UnsafeByteArrayOutputStream : ByteArrayOutputStream {

    constructor() : super(32) {}

    constructor(size: Int) : super(size) {}

    /**
     * Writes the specified byte to this byte array output stream.
     *
     * @param b the byte to be written.
     */
    override fun write(b: Int) {
        val newcount = count + 1
        if (newcount > buf.size) {
            buf = Utils.copyOf(buf, Math.max(buf.size shl 1, newcount))
        }
        buf[count] = b.toByte()
        count = newcount
    }

    /**
     * Writes `len` bytes from the specified byte array
     * starting at offset `off` to this byte array output stream.
     *
     * @param b   the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     */
    override fun write(b: ByteArray, off: Int, len: Int) {
        if (off < 0 || off > b.size || len < 0 ||
                off + len > b.size || off + len < 0) {
            throw IndexOutOfBoundsException()
        } else if (len == 0) {
            return
        }
        val newcount = count + len
        if (newcount > buf.size) {
            buf = Utils.copyOf(buf, Math.max(buf.size shl 1, newcount))
        }
        System.arraycopy(b, off, buf, count, len)
        count = newcount
    }

    /**
     * Writes the complete contents of this byte array output stream to
     * the specified output stream argument, as if by calling the output
     * stream's write method using `out.write(buf, 0, count)`.
     *
     * @param out the output stream to which to write the data.
     * @throws IOException if an I/O error occurs.
     */
    @Throws(IOException::class)
    override fun writeTo(out: OutputStream) {
        out.write(buf, 0, count)
    }

    /**
     * Resets the `count` field of this byte array output
     * stream to zero, so that all currently accumulated output in the
     * output stream is discarded. The output stream can be used again,
     * reusing the already allocated buffer space.
     *
     * @see java.io.ByteArrayInputStream.count
     */
    override fun reset() {
        count = 0
    }

    /**
     * Creates a newly allocated byte array. Its size is the current
     * size of this output stream and the valid contents of the buffer
     * have been copied into it.
     *
     * @return the current contents of this output stream, as a byte array.
     * @see java.io.ByteArrayOutputStream.size
     */
    override fun toByteArray(): ByteArray {
        return if (count == buf.size) buf else Utils.copyOf(buf, count)
    }

    /**
     * Returns the current size of the buffer.
     *
     * @return the value of the `count` field, which is the number
     * of valid bytes in this output stream.
     * @see java.io.ByteArrayOutputStream.count
     */
    override fun size(): Int {
        return count
    }

}
