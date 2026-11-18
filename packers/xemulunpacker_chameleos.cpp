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
#include "xemulunpacker_chameleos.h"

XEmulUnpackerChameleos::XEmulUnpackerChameleos(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerChameleos::getPackerName() const
{
    return QStringLiteral("Chameleos");
}

XEmulUnpacker::OPTIONS XEmulUnpackerChameleos::getDefaultOptions() const
{
    OPTIONS options;
    
    // Chameleos decrypts (ROR 3 + ADD with a 32-byte key) and LZ4-decompresses 
    // each packed section in-place, with inline polymorphic junk instructions 
    // (0xCC / 0xDD markers) scattered throughout the stub.
    options.nMaxSteps = 50000000; 
    
    // The stub runs from an appended section (e.g. .text1, .rdata1) and 
    // overwrites the original sections in-place before jumping back to OEP.
    options.bDetectSectionHop = true;
    options.bDetectWriteExec = true;
    
    return options;
}

bool XEmulUnpackerChameleos::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // The stub resides in the highest appended section and jumps down 
    // into the unpacked original section once LZ4 decompression finishes.
    if (c.bJumpFromHigh && c.bCurrIsImage) {
        
        // Since orig_entry is read from the metadata table at meta_rva and 
        // added to ImageBase at runtime, the stub transfers control via a 
        // register jump (FF E0 .. FF E7, e.g. jmp rax / jmp eax).
        if (c.nPrevSize == 2) {
            quint16 opcode = c.prev16();
            if (opcode >= 0xE0FF && opcode <= 0xE7FF) {
                return true;
            }
        }

        // Also cover x64 extended register jumps (41 FF E0 .. 41 FF E7, e.g. jmp r8..r15)
        if (c.nPrevSize == 3 && c.prev16() == 0xFF41) {
            return true;
        }

        // Fallback if the stub uses push + ret (C3) to transfer control
        if (c.nPrevSize == 1 && c.prev8() == 0xC3) {
            return true;
        }
    }

    return false;
}