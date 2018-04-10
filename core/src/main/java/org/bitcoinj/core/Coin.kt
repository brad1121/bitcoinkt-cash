/*
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

import org.bitcoinj.utils.MonetaryFormat
import com.google.common.math.LongMath
import com.google.common.primitives.Longs

import java.io.Serializable
import java.math.BigDecimal

import com.google.common.base.Preconditions.checkArgument
import org.bitcoinj.core.Coin.Companion.CENT
import org.bitcoinj.core.Coin.Companion.COIN

/**
 * Represents a monetary Bitcoin value. This class is immutable.
 */
class Coin private constructor(
        /**
         * The number of satoshis of this monetary value.
         */
        /**
         * Returns the number of satoshis of this monetary value.
         */
        override val value: Long) : Monetary, Comparable<Coin>, Serializable {

    /**
     * Returns true if and only if this instance represents a monetary value greater than zero,
     * otherwise false.
     */
    val isPositive: Boolean
        get() = signum() == 1

    /**
     * Returns true if and only if this instance represents a monetary value less than zero,
     * otherwise false.
     */
    val isNegative: Boolean
        get() = signum() == -1

    /**
     * Returns true if and only if this instance represents zero monetary value,
     * otherwise false.
     */
    val isZero: Boolean
        get() = signum() == 0

    override fun smallestUnitExponent(): Int {
        return SMALLEST_UNIT_EXPONENT
    }

    fun add(value: Coin): Coin {
        return Coin(LongMath.checkedAdd(this.value, value.value))
    }

    /** Alias for add  */
    operator fun plus(value: Coin): Coin {
        return add(value)
    }

    fun subtract(value: Coin): Coin {
        return Coin(LongMath.checkedSubtract(this.value, value.value))
    }

    /** Alias for subtract  */
    operator fun minus(value: Coin): Coin {
        return subtract(value)
    }

    fun multiply(factor: Long): Coin {
        return Coin(LongMath.checkedMultiply(this.value, factor))
    }

    /** Alias for multiply  */
    operator fun times(factor: Long): Coin {
        return multiply(factor)
    }

    /** Alias for multiply  */
    operator fun times(factor: Int): Coin {
        return multiply(factor.toLong())
    }

    fun divide(divisor: Long): Coin {
        return Coin(this.value / divisor)
    }

    /** Alias for divide  */
    operator fun div(divisor: Long): Coin {
        return divide(divisor)
    }

    /** Alias for divide  */
    operator fun div(divisor: Int): Coin {
        return divide(divisor.toLong())
    }

    fun divideAndRemainder(divisor: Long): Array<Coin> {
        return arrayOf(Coin(this.value / divisor), Coin(this.value % divisor))
    }

    fun divide(divisor: Coin): Long {
        return this.value / divisor.value
    }

    /**
     * Returns true if the monetary value represented by this instance is greater than that
     * of the given other Coin, otherwise false.
     */
    fun isGreaterThan(other: Coin): Boolean {
        return compareTo(other) > 0
    }

    /**
     * Returns true if the monetary value represented by this instance is less than that
     * of the given other Coin, otherwise false.
     */
    fun isLessThan(other: Coin): Boolean {
        return compareTo(other) < 0
    }

    fun shiftLeft(n: Int): Coin {
        return Coin(this.value shl n)
    }

    fun shiftRight(n: Int): Coin {
        return Coin(this.value shr n)
    }

    override fun signum(): Int {
        if (this.value == 0L)
            return 0
        return if (this.value < 0) -1 else 1
    }

    fun negate(): Coin {
        return Coin(-this.value)
    }

    /**
     * Returns the number of satoshis of this monetary value. It's deprecated in favour of accessing [.value]
     * directly.
     */
    fun longValue(): Long {
        return this.value
    }

    /**
     * Returns the value as a 0.12 type string. More digits after the decimal place will be used
     * if necessary, but two will always be present.
     */
    fun toFriendlyString(): String {
        return FRIENDLY_FORMAT.format(this).toString()
    }

    /**
     *
     *
     * Returns the value as a plain string denominated in BTC.
     * The result is unformatted with no trailing zeroes.
     * For instance, a value of 150000 satoshis gives an output string of "0.0015" BTC
     *
     */
    fun toPlainString(): String {
        return PLAIN_FORMAT.format(this).toString()
    }

    override fun toString(): String {
        return java.lang.Long.toString(value)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        return if (o == null || javaClass != o.javaClass) false else this.value == (o as Coin).value
    }

    override fun hashCode(): Int {
        return this.value.toInt()
    }

    override fun compareTo(other: Coin): Int {
        return Longs.compare(this.value, other.value)
    }

    companion object {

        /**
         * Number of decimals for one Bitcoin. This constant is useful for quick adapting to other coins because a lot of
         * constants derive from it.
         */
        val SMALLEST_UNIT_EXPONENT = 8

        /**
         * The number of satoshis equal to one bitcoin.
         */
        private val COIN_VALUE = LongMath.pow(10, SMALLEST_UNIT_EXPONENT)

        /**
         * Zero Bitcoins.
         */
        val ZERO = Coin.valueOf(0)

        /**
         * One Bitcoin.
         */
        val COIN = Coin.valueOf(COIN_VALUE)

        /**
         * 0.01 Bitcoins. This unit is not really used much.
         */
        val CENT = COIN.divide(100)

        /**
         * 0.001 Bitcoins, also known as 1 mBTC.
         */
        val MILLICOIN = COIN.divide(1000)

        /**
         * 0.000001 Bitcoins, also known as 1 µBTC or 1 uBTC.
         */
        val MICROCOIN = MILLICOIN.divide(1000)

        /**
         * A satoshi is the smallest unit that can be transferred. 100 million of them fit into a Bitcoin.
         */
        val SATOSHI = Coin.valueOf(1)

        val FIFTY_COINS = COIN.multiply(50)

        /**
         * Represents a monetary value of minus one satoshi.
         */
        val NEGATIVE_SATOSHI = Coin.valueOf(-1)

        fun valueOf(satoshis: Long): Coin {
            return Coin(satoshis)
        }

        /**
         * Convert an amount expressed in the way humans are used to into satoshis.
         */
        fun valueOf(coins: Int, cents: Int): Coin {
            checkArgument(cents < 100)
            checkArgument(cents >= 0)
            checkArgument(coins >= 0)
            return COIN.multiply(coins.toLong()).add(CENT.multiply(cents.toLong()))
        }

        /**
         * Parses an amount expressed in the way humans are used to.
         *
         *
         *
         *
         * This takes string in a format understood by [BigDecimal.BigDecimal],
         * for example "0", "1", "0.10", "1.23E3", "1234.5E-5".
         *
         * @throws IllegalArgumentException if you try to specify fractional satoshis, or a value out of range.
         */
        fun parseCoin(str: String): Coin {
            try {
                val satoshis = BigDecimal(str).movePointRight(SMALLEST_UNIT_EXPONENT).toBigIntegerExact().toLong()
                return Coin.valueOf(satoshis)
            } catch (e: ArithmeticException) {
                throw IllegalArgumentException(e) // Repackage exception to honor method contract
            }

        }

        private val FRIENDLY_FORMAT = MonetaryFormat.BTC.minDecimals(2).repeatOptionalDecimals(1, 6).postfixCode()

        private val PLAIN_FORMAT = MonetaryFormat.BTC.minDecimals(0).repeatOptionalDecimals(1, 8).noCode()
    }
}
