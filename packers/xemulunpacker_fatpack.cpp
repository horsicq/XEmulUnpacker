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
#include "xemulunpacker_fatpack.h"

XEmulUnpackerFatpack::XEmulUnpackerFatpack(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerFatpack::getPackerName() const
{
    return QStringLiteral("Fatpack (x64 LZMA Manual Mapper)");
}

XEmulUnpacker::OPTIONS XEmulUnpackerFatpack::getDefaultOptions() const
{
    OPTIONS options;
    // Fatpack uses intensive LZMA decompression, Import Resolving, and TLS initialization.
    // We need a significantly higher step limit to allow the emulated loader to finish.
    options.nMaxSteps = 50000000;
    return options;
}

bool XEmulUnpackerFatpack::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // Fatpack is strictly an x64 packer. Do not attempt to match on 32-bit x86 code.
    if (!c.bIs64) {
        return false;
    }

    // Since Fatpack is a Manual Mapper, the unpacked executable is placed in a newly
    // allocated VirtualAlloc memory block. These dynamic allocations reside in high memory.
    if (!c.bJumpToHigh) {
        return false;
    }

    // In a 64-bit C/C++ Manual Mapper, executing the OEP function pointer usually
    // compiles down to an indirect register call or jump.
    // Example: call rax, call rcx, jmp rdx.

    // Pattern 1: 'call reg' (x64 indirect call via standard 64-bit register, e.g., RAX, RCX)
    // Opcodes: FF D0 to FF D7
    if ((c.nPrevSize >= 2) && (c.prev16() >= 0xD0FF && c.prev16() <= 0xD7FF)) {
        return true;
    }

    // Pattern 2: 'jmp reg' (x64 indirect jump via standard 64-bit register)
    // Opcodes: FF E0 to FF E7
    if ((c.nPrevSize >= 2) && (c.prev16() >= 0xE0FF && c.prev16() <= 0xE7FF)) {
        return true;
    }

    // Pattern 3: REX-prefixed 'call reg' or 'jmp reg' for extended x64 registers (R8-R15)
    // Opcodes: 41 FF D0 (call r8) or 41 FF E0 (jmp r8)
    if (c.nPrevSize >= 3) {
        if (c.matchSignature(c.nPrevAddress - c.nPrevSize, "41FFD?")) {
            return true;
        }
        if (c.matchSignature(c.nPrevAddress - c.nPrevSize, "41FFE?")) {
            return true;
        }
    }

    return false;
}
