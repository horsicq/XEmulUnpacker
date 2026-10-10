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
#include "xemulunpacker_neolite.h"

XEmulUnpackerNeoLite::XEmulUnpackerNeoLite(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerNeoLite::getPackerName() const
{
    return QStringLiteral("NeoLite");
}

XEmulUnpacker::OPTIONS XEmulUnpackerNeoLite::getDefaultOptions() const
{
    OPTIONS options;
    // NeoLite unpacker stubs decompress zlib/custom streams and rebuild sections.
    // 10,000,000 steps are more than sufficient to complete the unpacking loop.
    options.nMaxSteps = 10000000;
    return options;
}

bool XEmulUnpackerNeoLite::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // NeoLite primarily targets 32-bit (x86) binaries.
    if (c.bIs64) {
        return false;
    }

    // NeoLite is a classical section-packer.
    // It restores the code in-place into the PE sections, so it should not jump to high memory.
    if (c.bJumpToHigh) {
        return false;
    }

    // The stack must be balanced after the unpacker stub finishes its routines.
    if (c.nSpDelta != 0) {
        return false;
    }

    // Pattern 1: Standard relative 5-byte jump (E9 XX XX XX XX) to original entry point
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }

    // Pattern 2: 'push imm32' (68) followed by 'ret' (C3)
    if ((c.nPrevSize == 1) && (c.prev8() == 0xC3)) {
        if (c.matchSignature(c.nPrevAddress - 5, "68........")) {
            return true;
        }
    }

    // Pattern 3: Indirect jump via 32-bit register (e.g., jmp eax, jmp ecx)
    // Opcodes: FF E0 to FF E7 -> Little Endian: 0xE0FF to 0xE7FF
    if ((c.nPrevSize == 2) && (c.prev16() >= 0xE0FF && c.prev16() <= 0xE7FF)) {
        return true;
    }

    return false;
}
