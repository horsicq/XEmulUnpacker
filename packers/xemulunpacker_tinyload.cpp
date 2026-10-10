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
#include "xemulunpacker_tinyload.h"

XEmulUnpackerTinyLoad::XEmulUnpackerTinyLoad(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerTinyLoad::getPackerName() const
{
    return QStringLiteral("TinyLoad");
}

XEmulUnpacker::OPTIONS XEmulUnpackerTinyLoad::getDefaultOptions() const
{
    OPTIONS options;
    // TinyLoad employs a custom 28-opcode Virtual Machine to run a stream cipher,
    // applies XXTEA decryption, and uses a VEH (Vectored Exception Handler) for page faults.
    // Emulating a VM executing cryptographic routines requires a colossal amount of CPU cycles.
    // We max out the step limit to ensure the emulator doesn't time out prematurely.
    options.nMaxSteps = 150000000;
    return options;
}

bool XEmulUnpackerTinyLoad::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    if (!c.bIs64) {
        return false;
    }

    // TinyLoad executes the payload directly in memory (Manual Mapping).
    // The payload is deployed into dynamically allocated memory blocks,
    // so the OEP jump MUST point into high memory.
    if (!c.bJumpToHigh) {
        return false;
    }

    // Pattern 1: 'call reg' (indirect call via standard 64-bit register, e.g., RAX, RCX)
    // Opcodes: FF D0 to FF D7 -> Little Endian: 0xD0FF to 0xD7FF
    if ((c.nPrevSize >= 2) && (c.prev16() >= 0xD0FF && c.prev16() <= 0xD7FF)) {
        return true;
    }

    // Pattern 2: 'jmp reg' (indirect jump via standard 64-bit register)
    // Opcodes: FF E0 to FF E7 -> Little Endian: 0xE0FF to 0xE7FF
    if ((c.nPrevSize >= 2) && (c.prev16() >= 0xE0FF && c.prev16() <= 0xE7FF)) {
        return true;
    }

    // Pattern 3: REX-prefixed 'call reg' or 'jmp reg' for extended x64 registers (r8-r15)
    // The C++ compiler frequently leverages these extended registers for function pointers.
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
