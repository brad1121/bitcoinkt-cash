/*
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

package org.bitcoinj.core.listeners

import org.bitcoinj.core.*

import java.util.*

/**
 * For backwards compatibility only. Implements the block chain listener interfaces. Use the more specific interfaces
 * instead.
 */
@Deprecated("")
class AbstractBlockChainListener : BlockChainListener {
    @Throws(VerificationException::class)
    override fun notifyNewBestBlock(block: StoredBlock) {
    }

    @Throws(VerificationException::class)
    override fun reorganize(splitPoint: StoredBlock, oldBlocks: List<StoredBlock>, newBlocks: List<StoredBlock>) {
    }

    @Throws(VerificationException::class)
    override fun receiveFromBlock(tx: Transaction, block: StoredBlock, blockType: BlockChain.NewBlockType, relativityOffset: Int) {
    }

    @Throws(VerificationException::class)
    override fun notifyTransactionIsInBlock(txHash: Sha256Hash, block: StoredBlock, blockType: BlockChain.NewBlockType, relativityOffset: Int): Boolean {
        return false
    }
}
