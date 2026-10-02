/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xemulunpacker_troglodyte9.h"

XEmulUnpackerTroglodyte9::XEmulUnpackerTroglodyte9(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerTroglodyte9::getPackerName() const
{
    return QStringLiteral("troglodyte9");
}

XEmulUnpacker::OPTIONS XEmulUnpackerTroglodyte9::getDefaultOptions() const
{
    OPTIONS options;
    // The packer uses a simple Linear Congruential Generator (LCG) loop for decryption.
    // 5,000,000 steps are usually more than enough to decrypt the regions.
    options.nMaxSteps = 5000000; 
    return options;
}

bool XEmulUnpackerTroglodyte9::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    
    // troglodyte9 provides native stubs for both x86 and x64.
    // Therefore, no architecture check is needed here.

    // Decryption is strictly in-place. The stub parses its 'regions' array and 
    // modifies the original mapped PE sections. No execution in dynamic heap.
    if (c.bJumpToHigh) {
        return false;
    }

    // The x64 stub uses lea/rip-relative addressing and doesn't touch the stack.
    // The x86 stub uses a perfectly balanced 'call / pop ebp' delta-offset trick.
    // Thus, the stack delta must remain 0 in both architectures.
    if (c.nSpDelta != 0) {
        return false;
    }

    // Pattern 1: Indirect jump via register (jmp eax / jmp rax)
    // The stub explicitly ends with 'jmp eax' on x86 and 'jmp rax' on x64.
    // Both compile to the opcode FF E0. We check the whole FF E0 to FF E7 range.
    // Little Endian: 0xE0FF to 0xE7FF
    if ((c.nPrevSize == 2) && (c.prev16() >= 0xE0FF && c.prev16() <= 0xE7FF)) {
        return true;
    }

    return false;
}