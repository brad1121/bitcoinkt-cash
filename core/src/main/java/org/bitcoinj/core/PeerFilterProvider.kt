/*
 * Copyright 2013 Google Inc.
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
 * An interface which provides the information required to properly filter data downloaded from Peers.
 * Note that an implementer is responsible for calling [PeerGroup.recalculateFastCatchupAndFilter]
 * whenever a change occurs which effects the data provided via this interface.
 */
interface PeerFilterProvider {
    /**
     * Returns the earliest timestamp (seconds since epoch) for which full/bloom-filtered blocks must be downloaded.
     * Blocks with timestamps before this time will only have headers downloaded. 0 requires that all blocks be
     * downloaded, and thus this should default to [System.currentTimeMillis]/1000.
     */
    val earliestKeyCreationTime: Long


    /**
     * Gets the number of elements that will be added to a bloom filter returned by
     * [PeerFilterProvider.getBloomFilter]
     */
    val bloomFilterElementCount: Int

    /** Whether this filter provider depends on the server updating the filter on all matches  */
    val isRequiringUpdateAllBloomFilter: Boolean

    /**
     * Called on all registered filter providers before getBloomFilterElementCount and getBloomFilter are called.
     * Once called, the provider should ensure that the items it will want to insert into the filter don't change.
     * The reason is that all providers will have their element counts queried, and then a filter big enough for
     * all of them will be specified. So the provider must use consistent state. There is guaranteed to be a matching
     * call to endBloomFilterCalculation that can be used to e.g. unlock a lock.
     */
    fun beginBloomFilterCalculation()

    /**
     * Gets a bloom filter that contains all the necessary elements for the listener to receive relevant transactions.
     * Default value should be an empty bloom filter with the given size, falsePositiveRate, and nTweak.
     */
    fun getBloomFilter(size: Int, falsePositiveRate: Double, nTweak: Long): BloomFilter

    fun endBloomFilterCalculation()
}
