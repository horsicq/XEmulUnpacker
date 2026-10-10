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
#include "xemulunpacker_npack.h"

#include "xemumemorymanager.h"

XEmulUnpackerNPack::XEmulUnpackerNPack(QObject *pParent) : XEmulUnpacker(pParent)
{
}

QString XEmulUnpackerNPack::getPackerName() const
{
    return QStringLiteral("nPack");
}

XEmulUnpacker::OPTIONS XEmulUnpackerNPack::getDefaultOptions() const
{
    OPTIONS options;
    options.nMaxSteps = 40000000;
    return options;
}

bool XEmulUnpackerNPack::matchOEP(const OEP_CONTEXT &c, const OPTIONS &options) const
{
    Q_UNUSED(options)
    // nPack: 'ret' (C3) from a higher page, balanced stack.
    return c.bJumpFromHigh && (c.nPrevSize == 1) && (c.nSpDelta == 0) && (c.prev8() == 0xC3);
}

quint64 XEmulUnpackerNPack::recoverOepAtStop(XEmuMemoryManager *pMemoryManager, quint64 nScanStart, quint64 nScanEnd, quint64 nImageBase, quint64 nImageSize) const
{
    // The nPack stub tail is `add [P],eax ; push [P] ; ret` == 01 05 <P32> ..(<=32B).. FF 35 <P32> C3
    // (same absolute pointer P). [P] holds the preferred-absolute OEP, written by the metadata
    // decompressor before the tail runs. For the larger bcb image the aPLib depacker faults before
    // the C3 ret retires, so matchOEP never fires; recover the OEP by finding this tail in the entry
    // section and reading *P.
    const quint64 nLen = (nScanEnd > nScanStart) ? (nScanEnd - nScanStart) : 0;
    if ((nLen == 0) || (nLen > 0x100000)) {
        return 0;
    }
    bool bOk = false;
    const QByteArray ba = pMemoryManager->read(nScanStart, nLen, &bOk);
    if (!bOk || ba.isEmpty()) {
        return 0;
    }
    const int n = ba.size();
    const uchar *p = reinterpret_cast<const uchar *>(ba.constData());
    for (int i = 0; i + 6 <= n; i++) {
        if ((p[i] != 0x01) || (p[i + 1] != 0x05)) {
            continue;
        }
        const quint32 nP = (quint32)p[i + 2] | ((quint32)p[i + 3] << 8) | ((quint32)p[i + 4] << 16) | ((quint32)p[i + 5] << 24);
        for (int j = i + 6; (j + 7 <= n) && (j <= i + 38); j++) {
            const quint32 nP2 = (quint32)p[j + 2] | ((quint32)p[j + 3] << 8) | ((quint32)p[j + 4] << 16) | ((quint32)p[j + 5] << 24);
            if ((p[j] == 0xFF) && (p[j + 1] == 0x35) && (p[j + 6] == 0xC3) && (nP2 == nP)) {
                bool bOk2 = false;
                const quint32 nOep = pMemoryManager->readDword(nP, &bOk2);
                if (bOk2 && (nOep >= nImageBase) && (nOep < nImageBase + nImageSize)) {
                    return nOep;
                }
            }
        }
    }
    return 0;
}
