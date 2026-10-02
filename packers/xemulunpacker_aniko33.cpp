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
#include "xemulunpacker_aniko33.h"

XEmulUnpackerAniko33::XEmulUnpackerAniko33(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerAniko33::getPackerName() const
{
    return QStringLiteral("aniko33");
}

XEmulUnpacker::OPTIONS XEmulUnpackerAniko33::getDefaultOptions() const
{
    OPTIONS options;
    // aniko33 is a straightforward manual mapper. It does not use heavy compression 
    // algorithms. It simply copies sections, resolves the IAT, and applies relocations.
    // 10,000,000 steps are more than enough.
    options.nMaxSteps = 10000000; 
    return options;
}

bool XEmulUnpackerAniko33::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    
    // The stub explicitly uses IMAGE_NT_HEADERS64 and IMAGE_THUNK_DATA64.
    // It is strictly a 64-bit manual mapper.
    if (!c.bIs64) {
        return false;
    }

    // The packer uses VirtualAlloc to map the payload into executable memory
    // (if dynamic base is supported, which is the default for modern PEs).
    // Execution transitions to this high-memory heap.
    if (!c.bJumpToHigh) {
        return false;
    }

    // The OEP transfer happens via a C-style function pointer call:
    // ((void (*)(void)) start_address)();
    // Since it is compiled with a C/C++ compiler, the epilogue dictates the stack state.
    // We DO NOT check c.nSpDelta.

    if (c.nPrevSize == 2) {
        // Pattern 1: call reg (e.g., call rax, call rcx) -> FF D0 to FF D7
        if (c.prev16() >= 0xD0FF && c.prev16() <= 0xD7FF) {
            return true;
        }
        // Pattern 2: jmp reg (e.g., jmp rax) -> FF E0 to FF E7
        if (c.prev16() >= 0xE0FF && c.prev16() <= 0xE7FF) {
            return true;
        }
    }
    else if (c.nPrevSize >= 3 && c.prev8() == 0xFF) {
        quint8 secondByte = (c.prev16() >> 8) & 0xFF;
        
        // Pattern 3: call [mem] variants 
        // FF 15 (call qword ptr [rip+disp32]), FF 5? (call qword ptr [reg+disp8]), etc.
        if (secondByte == 0x15 || (secondByte >= 0x50 && secondByte <= 0x57) || (secondByte >= 0x90 && secondByte <= 0x97)) {
            return true;
        }
        // Pattern 4: jmp [rip+disp32] (FF 25)
        if (secondByte == 0x25) {
            return true;
        }
    }

    return false;
}