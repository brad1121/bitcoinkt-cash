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

open class VerificationException : RuntimeException {
    constructor(msg: String) : super(msg) {}

    constructor(e: Exception) : super(e) {}

    constructor(msg: String, t: Throwable) : super(msg, t) {}

    class EmptyInputsOrOutputs : VerificationException("Transaction had no inputs or no outputs.")

    class LargerThanMaxBlockSize : VerificationException("Transaction larger than MAX_BLOCK_SIZE")

    class DuplicatedOutPoint : VerificationException("Duplicated outpoint")

    class NegativeValueOutput : VerificationException("Transaction output negative")

    class ExcessiveValue : VerificationException("Total transaction output value greater than possible")


    class CoinbaseScriptSizeOutOfRange : VerificationException("Coinbase script size out of range")


    class BlockVersionOutOfDate(version: Long) : VerificationException("Block version #"
            + version + " is outdated.")

    class UnexpectedCoinbaseInput : VerificationException("Coinbase input as input in non-coinbase transaction")

    class CoinbaseHeightMismatch(message: String) : VerificationException(message)
}
