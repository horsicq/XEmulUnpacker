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
#include "xemulunpacker_xorpacker.h"

XEmulUnpackerXorPacker::XEmulUnpackerXorPacker(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerXorPacker::getPackerName() const
{
    return QStringLiteral("xor-packer");
}

XEmulUnpacker::OPTIONS XEmulUnpackerXorPacker::getDefaultOptions() const
{
    OPTIONS options;
    // The unpacker stub uses a lightweight RCX loop to XOR-decrypt the code section in-place.
    // 5,000,000 steps are more than enough to complete the loop instantly.
    options.nMaxSteps = 5000000;
    return options;
}

bool XEmulUnpackerXorPacker::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)

    // The unpacker script relies entirely on x64 registers (RAX, RCX) and REX prefixes.
    if (!c.bIs64) {
        return false;
    }

    // The stub decrypts the .text section in-place and appends a '.new' section.
    // It does not allocate new virtual memory via VirtualAlloc (no Manual Mapping).
    if (c.bJumpToHigh) {
        return false;
    }

    // As generated in generate_unpacker_x64(), the stub finishes the decryption loop
    // and directly executes a relative 32-bit jump (E9 XX XX XX XX) back to the OEP.
    if ((c.nPrevSize == 5) && (c.prev8() == 0xE9)) {
        return true;
    }

    return false;
}
