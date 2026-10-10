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
#include "xemulunpacker_packedinfectedpe.h"

XEmulUnpackerPackedInfectedPE::XEmulUnpackerPackedInfectedPE(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerPackedInfectedPE::getPackerName() const
{
    return QStringLiteral("Packed-Infected-PE");
}

XEmulUnpacker::OPTIONS XEmulUnpackerPackedInfectedPE::getDefaultOptions() const
{
    OPTIONS options;
    // Step limit to allow anti-debug checks, CPUID VM checks, API resolution,
    // Shellcode MessageBox execution, and the final jump to finish.
    options.nMaxSteps = 10000000;
    return options;
}

bool XEmulUnpackerPackedInfectedPE::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // The packer heavily relies on 32-bit specific structures (IMAGE_NT_HEADERS32)
    // and 32-bit inline assembly (eax, ebx, fs:0x30).
    if (c.bIs64) {
        return false;
    }

    // CRITICAL: We DO NOT check c.nSpDelta!
    // The stub is a standard C function that jumps away directly via inline ASM (jmp 0x12345678).
    // It skips the C compiler's epilogue, leaving the stack frame completely imbalanced.

    // CRITICAL: We DO NOT check c.bJumpToHigh!
    // The packer infects existing code caves or adds a section. The final jump returns
    // to the original PE section, which is part of the mapped image, not a dynamic heap.

    // The final transfer is a standard 5-byte relative jump (E9 XX XX XX XX).
    // The packer's adjustUnpack() function patches this jump dynamically.
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }

    return false;
}
