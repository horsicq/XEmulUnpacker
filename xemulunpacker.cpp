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
#include "xemulunpacker.h"

#include <algorithm>
#include <cstring>

#include <QFile>

#include "xpe.h"

static inline void wr16(char *p, quint16 v)
{
    p[0] = (char)(v & 0xff);
    p[1] = (char)((v >> 8) & 0xff);
}
static inline void wr32(char *p, quint32 v)
{
    p[0] = (char)(v & 0xff);
    p[1] = (char)((v >> 8) & 0xff);
    p[2] = (char)((v >> 16) & 0xff);
    p[3] = (char)((v >> 24) & 0xff);
}
static inline void wr64(char *p, quint64 v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (char)((v >> (i * 8)) & 0xff);
    }
}
static inline quint32 alignUp32(quint32 v, quint32 a)
{
    return (v + a - 1) & ~(a - 1);
}

// A committed image region turned into a rebuilt-PE section.
struct GU_SECTION {
    quint32 nRva;
    quint32 nSize;
    QByteArray baData;
};

// One reconstructed import: the IAT slot (RVA) the packer filled and the name it resolved to.
struct GU_IMPORT {
    quint32 nSlotRva;   // RVA of the IAT slot (FirstThunk entry) inside the dumped image
    QString sLibrary;   // DLL name (original case)
    QString sFunction;  // export name (empty for by-ordinal)
    qint64 nOrdinal;    // -1 for by-name
};

static bool guImportSlotLess(const GU_IMPORT &a, const GU_IMPORT &b)
{
    return a.nSlotRva < b.nSlotRva;
}

static bool guSectionRvaLess(const GU_SECTION &a, const GU_SECTION &b)
{
    return a.nRva < b.nRva;
}

// A committed image region turned into a rebuilt-Mach-O segment.
struct GU_SEGMENT {
    quint64 nAddr;
    quint64 nSize;
    QByteArray baData;
};

static bool guSegmentAddrLess(const GU_SEGMENT &a, const GU_SEGMENT &b)
{
    return a.nAddr < b.nAddr;
}

// Little-endian read of up to 8 bytes from emulated memory.
static quint64 guReadMem(XEmuMemoryManager *pMemoryManager, XADDR nAddr, int nBytes)
{
    quint64 nValue = 0;
    for (int i = 0; i < nBytes; i++) {
        bool bOk = false;
        nValue |= (quint64)pMemoryManager->readByte(nAddr + i, &bOk) << (i * 8);
    }
    return nValue;
}

// A stable snapshot of one committed image section, used to classify a PC during OEP scanning.
struct GU_SECRANGE {
    quint64 nStart;
    quint64 nEnd;
};

// Index of the snapshot section that contains nAddr, or -1 if none.
static int guSectionOf(const QList<GU_SECRANGE> &listSecRanges, quint64 nAddr)
{
    for (int i = 0; i < listSecRanges.size(); i++) {
        if ((nAddr >= listSecRanges.at(i).nStart) && (nAddr < listSecRanges.at(i).nEnd)) {
            return i;
        }
    }
    return -1;
}

// Write-callback function object: records the in-image pages the stub writes to, and the
// IAT slots it fills with resolved-import pointers (for import-table reconstruction).
// Passed to XEmuMemoryManager::setWriteCallback in place of a capturing lambda.
struct GU_DirtyPageWatcher {
    QSet<quint64> *pDirtyPages;
    quint64 nImageBase;
    quint64 nImageSize;
    quint64 nPageMask;
    QMap<quint64, quint64> *pIatSlots;  // in-image IAT slot (abs addr) -> emulated-API stub value
    quint64 nStubBase;
    quint64 nStubLimit;
    int nPtrSize;  // IAT slot width: 4 (PE32) or 8 (PE32+)

    void operator()(XADDR nAddress, quint32 nSize, quint64 nValue) const
    {
        if ((nAddress + nSize <= nImageBase) || (nAddress >= nImageBase + nImageSize)) {
            return;  // writes outside the image (stack, heap, control structures) are irrelevant
        }
        quint64 nFirst = nAddress & nPageMask;
        quint64 nLast = (nAddress + nSize - 1) & nPageMask;
        for (quint64 nPage = nFirst; nPage <= nLast; nPage += XEmuMemoryManager::N_PAGE_SIZE) {
            pDirtyPages->insert(nPage);
        }
        // A pointer-sized, pointer-aligned write whose value points into the emulated-API arena
        // is the packer filling an IAT slot with a resolved import (32-bit slots are dwords,
        // 64-bit slots are qwords -- a stub address fits in the low 32 bits either way, so the
        // same range test applies). Record it (last write wins) so the dump can carry a rebuilt
        // import directory the real loader will re-resolve. (The final-image scan is the
        // authoritative source; this is a hint for slots written after setup.)
        // Align on 4 (the minimum IAT-slot alignment) even for 64-bit: a PE32+ FirstThunk
        // array holds 8-byte entries but the array itself is only dword-aligned, so slots can
        // sit at 4-mod-8 RVAs.
        if ((pIatSlots != nullptr) && ((int)nSize == nPtrSize) && ((nAddress & 3) == 0) &&
            (nValue >= nStubBase) && (nValue < nStubLimit)) {
            (*pIatSlots)[nAddress] = nValue;
        }
    }
};

// infoMessage slot function object: filters the emulated OS calls into the API log.
// Connected to XEmuEmulator::infoMessage in place of a capturing lambda.
struct GU_ApiLogFilter {
    QStringList *pApiLog;
    int nMaxApiLog;

    void operator()(const QString &sText) const
    {
        if (pApiLog->size() >= nMaxApiLog) {
            return;
        }
        static const char *s_keys[] = {"VirtualAlloc(", "VirtualProtect(", "LoadLibraryA(", "GetProcAddress(", "mmap(",   "mprotect(", "msync(",
                                       "munmap(",       "memfd",           "open =",        "execve",         "write("};
        for (const char *pszKey : s_keys) {
            if (sText.contains(QLatin1String(pszKey))) {
                pApiLog->append(sText);
                break;
            }
        }
    }
};

XEmulUnpacker::XEmulUnpacker(QObject *pParent) : QObject(pParent)
{
}

XEmulUnpacker::~XEmulUnpacker()
{
}

// Build a reconstructed import directory blob for a new PE section at RVA nSecRva. Groups
// the recorded IAT slots into IMAGE_IMPORT_DESCRIPTORs (one per contiguous same-DLL run),
// with a fresh INT (OriginalFirstThunk) of IMAGE_IMPORT_BY_NAME pointers, and FirstThunk
// pointing at the existing (dumped) IAT slots so the real loader re-resolves them. Handles
// both PE32 (dword thunks/slots) and PE32+ (qword). Returns the blob (empty if nothing to
// build) and fills the directory RVA/size.
static QByteArray guBuildImportBlob(const QList<GU_IMPORT> &listImportsIn, quint32 nSecRva, bool bIs64,
                                    quint32 *pnDirRva, quint32 *pnDirSize)
{
    const quint32 nPtr = bIs64 ? 8u : 4u;                          // IMAGE_THUNK_DATA width
    const quint64 nOrdinalFlag = bIs64 ? 0x8000000000000000ULL : 0x80000000ULL;

    QList<GU_IMPORT> imps = listImportsIn;
    std::sort(imps.begin(), imps.end(), guImportSlotLess);
    if (imps.isEmpty()) {
        return QByteArray();
    }
    // No run/density filter is needed: the trampoline arena sits at a high, DLL-like base
    // (see XEmuWinApi::init), so a stub-range value can only be a real resolved import, not
    // a coincidental data constant. Every recorded slot is genuine.

    // Group consecutive, contiguous (pointer-stepped), same-DLL slots.
    struct GU_GROUP {
        QString sLib;
        int nStart;
        int nCount;
    };
    QList<GU_GROUP> groups;
    for (int i = 0; i < imps.size();) {
        int j = i + 1;
        while ((j < imps.size()) && (imps.at(j).sLibrary.compare(imps.at(i).sLibrary, Qt::CaseInsensitive) == 0) &&
               (imps.at(j).nSlotRva == imps.at(j - 1).nSlotRva + nPtr)) {
            j++;
        }
        GU_GROUP g;
        g.sLib = imps.at(i).sLibrary;
        g.nStart = i;
        g.nCount = j - i;
        groups.append(g);
        i = j;
    }
    const int nG = groups.size();
    if (nG == 0) {
        return QByteArray();
    }

    // --- layout pass (offsets relative to nSecRva) ---
    quint32 nOff = 0;
    const quint32 nDescOff = nOff;
    nOff += (quint32)(nG + 1) * 0x14;  // descriptors + null terminator
    while (bIs64 && (nOff & 7)) {
        nOff++;  // 8-align the thunk arrays for PE32+ (IMAGE_THUNK_DATA64)
    }

    std::vector<quint32> vIntRva(nG);
    for (int g = 0; g < nG; g++) {
        vIntRva[g] = nSecRva + nOff;
        nOff += (quint32)(groups.at(g).nCount + 1) * nPtr;  // thunks + null
    }
    std::vector<quint32> vNameRva(imps.size(), 0);
    for (int i = 0; i < imps.size(); i++) {
        if (!imps.at(i).sFunction.isEmpty()) {
            vNameRva[i] = nSecRva + nOff;
            nOff += 2 + (quint32)imps.at(i).sFunction.toLatin1().size() + 1;  // hint + name + NUL
            if (nOff & 1) {
                nOff++;  // IMAGE_IMPORT_BY_NAME is WORD-aligned
            }
        }
    }
    std::vector<quint32> vLibRva(nG);
    for (int g = 0; g < nG; g++) {
        vLibRva[g] = nSecRva + nOff;
        nOff += (quint32)groups.at(g).sLib.toLatin1().size() + 1;
    }

    // --- write pass ---
    QByteArray baBlob((int)nOff, (char)0);
    char *b = baBlob.data();  // b[k] == RVA (nSecRva + k)

    for (int g = 0; g < nG; g++) {
        char *d = b + (nDescOff + (quint32)g * 0x14);
        wr32(d + 0, vIntRva[g]);                                  // OriginalFirstThunk (INT)
        wr32(d + 12, vLibRva[g]);                                 // Name
        wr32(d + 16, imps.at(groups.at(g).nStart).nSlotRva);      // FirstThunk (existing IAT)
    }
    for (int g = 0; g < nG; g++) {
        char *t = b + (vIntRva[g] - nSecRva);
        for (int k = 0; k < groups.at(g).nCount; k++) {
            const GU_IMPORT &imp = imps.at(groups.at(g).nStart + k);
            quint64 nThunk;
            if (imp.sFunction.isEmpty() && (imp.nOrdinal >= 0)) {
                nThunk = nOrdinalFlag | (quint64)(imp.nOrdinal & 0xFFFF);  // IMAGE_ORDINAL_FLAG32/64
            } else {
                nThunk = vNameRva[groups.at(g).nStart + k];  // RVA to IMAGE_IMPORT_BY_NAME (fits in low 32 bits)
            }
            if (bIs64) {
                wr64(t + k * (int)nPtr, nThunk);
            } else {
                wr32(t + k * (int)nPtr, (quint32)nThunk);
            }
        }
        // null thunk terminator already zero
    }
    for (int i = 0; i < imps.size(); i++) {
        if (vNameRva[i] != 0) {
            char *n = b + (vNameRva[i] - nSecRva);
            QByteArray fn = imps.at(i).sFunction.toLatin1();
            memcpy(n + 2, fn.constData(), fn.size());  // hint (WORD) left 0
        }
    }
    for (int g = 0; g < nG; g++) {
        QByteArray ln = groups.at(g).sLib.toLatin1();
        memcpy(b + (vLibRva[g] - nSecRva), ln.constData(), ln.size());
    }

    if (pnDirRva) {
        *pnDirRva = nSecRva + nDescOff;
    }
    if (pnDirSize) {
        *pnDirSize = (quint32)(nG + 1) * 0x14;
    }
    return baBlob;
}

// Flatten the committed regions of [nBase, nBase+nSize) into a dense RVA-indexed buffer (zero
// where uncommitted). Used to diff two unpacked images for relocation reconstruction.
static QByteArray guCaptureImageBytes(XEmuMemoryManager *pMemoryManager, quint64 nBase, quint64 nSize)
{
    if (nSize == 0 || nSize > 0x40000000ULL) {
        return QByteArray();
    }
    QByteArray img((int)nSize, (char)0);
    const QList<XEmuMemoryManager::REGION> regions = pMemoryManager->getRegions();
    for (int i = 0; i < regions.size(); i++) {
        const XEmuMemoryManager::REGION &r = regions.at(i);
        if (r.state != XEmuMemoryManager::STATE_COMMIT) {
            continue;
        }
        quint64 a0 = qMax<quint64>(r.nAddress, nBase);
        quint64 a1 = qMin<quint64>(r.nAddress + r.nSize, nBase + nSize);
        if (a0 >= a1) {
            continue;
        }
        bool bOk = false;
        QByteArray bytes = pMemoryManager->read(a0, a1 - a0, &bOk);
        if (bOk && (bytes.size() > 0)) {
            memcpy(img.data() + (int)(a0 - nBase), bytes.constData(), bytes.size());
        }
    }
    return img;
}

// Run the stub a SECOND time with the main image forced to nBase2, single-stepping until it
// reaches the already-known OEP (nBase2 + nOepRva), then capture the unpacked image. Returns an
// empty buffer if the override did not take (image not relocatable) or the OEP was not reached.
static QByteArray guCaptureAtBase(const QString &sFileName, XEmuEmulator::OPTIONS emuOpt, quint64 nBase2, quint64 nOepRva, quint64 nImageSize,
                                  qint64 nMaxSteps, const std::atomic_bool *pStopFlag)
{
    emuOpt.nImageBaseOverride = nBase2;

    XEmuEmulator emu;
    if (!emu.loadFile(sFileName, emuOpt) || !emu.isReady()) {
        return QByteArray();
    }
    const QList<XEmuFileFormat::MODULE> mods = emu.getModules();
    if (mods.isEmpty() || (mods.at(0).nBaseAddress != nBase2)) {
        return QByteArray();  // the forced base was not honoured -> cannot diff
    }

    XEmuArch *pArch = emu.getArch();
    XEmuRegisters *pRegs = emu.getRegisters();
    const quint64 nTargetOEP = nBase2 + nOepRva;

    for (qint64 nSteps = 0; nSteps < nMaxSteps; nSteps++) {
        if (pStopFlag && pStopFlag->load()) {
            return QByteArray();
        }
        if ((quint64)pArch->getPC(pRegs) == nTargetOEP) {
            break;
        }
        XEmuArch::STEP_INFO si = emu.step();
        if (si.result != XEmuArch::STEP_OK) {
            break;
        }
    }
    if ((quint64)pArch->getPC(pRegs) != nTargetOEP) {
        return QByteArray();  // never reached the OEP at the second base
    }

    return guCaptureImageBytes(emu.getMemoryManager(), nBase2, nImageSize);
}

// Every RVA whose pointer-sized value moved by exactly nDelta between the two images is an
// absolute address that needs a base relocation. Deterministic emulation guarantees the two
// images are byte-identical everywhere else, so this has no false positives (unlike a single-
// image pointer scan). Scans byte-granular to catch unaligned fixups.
static QList<quint32> guDiffRelocs(const QByteArray &img1, const QByteArray &img2, quint64 nDelta, bool bIs64)
{
    QList<quint32> result;
    const int nPtr = bIs64 ? 8 : 4;
    const int n = qMin(img1.size(), img2.size());
    const uchar *p1 = (const uchar *)img1.constData();
    const uchar *p2 = (const uchar *)img2.constData();

    int rva = 0x1000;  // headers own [0,0x1000); no relocations there
    while (rva + nPtr <= n) {
        quint64 v1 = 0, v2 = 0;
        for (int k = 0; k < nPtr; k++) {
            v1 |= (quint64)p1[rva + k] << (k * 8);
            v2 |= (quint64)p2[rva + k] << (k * 8);
        }
        if ((v1 != 0) && ((v2 - v1) == nDelta)) {
            result.append((quint32)rva);
            rva += nPtr;  // this fixup field is consumed
        } else {
            rva += 1;
        }
    }
    return result;
}

// Build an IMAGE_BASE_RELOCATION directory (blocks grouped by 0x1000 page) from the fixup RVAs.
static QByteArray guBuildRelocBlob(const QList<quint32> &rvasIn, bool bIs64)
{
    if (rvasIn.isEmpty()) {
        return QByteArray();
    }
    QList<quint32> rvas = rvasIn;
    std::sort(rvas.begin(), rvas.end());
    const quint16 nType = bIs64 ? 10 : 3;  // IMAGE_REL_BASED_DIR64 / _HIGHLOW

    QByteArray blob;
    int i = 0;
    while (i < rvas.size()) {
        const quint32 nPage = rvas.at(i) & ~(quint32)0xFFF;
        std::vector<quint16> entries;
        while ((i < rvas.size()) && ((rvas.at(i) & ~(quint32)0xFFF) == nPage)) {
            entries.push_back((quint16)(((quint32)nType << 12) | (rvas.at(i) & 0xFFF)));
            i++;
        }
        if (entries.size() & 1) {
            entries.push_back(0);  // IMAGE_REL_BASED_ABSOLUTE pad -> block size stays a multiple of 4
        }
        const quint32 nBlockSize = 8 + (quint32)entries.size() * 2;
        const int nOff = blob.size();
        blob.resize(nOff + (int)nBlockSize);
        char *b = blob.data() + nOff;
        wr32(b + 0, nPage);
        wr32(b + 4, nBlockSize);
        for (size_t e = 0; e < entries.size(); e++) {
            wr16(b + 8 + (int)e * 2, entries[e]);
        }
    }
    return blob;
}

static QByteArray guBuildPE(XEmuMemoryManager *pMemoryManager, quint64 nImageBase, quint64 nImageSize, quint64 nOEP, bool bIs64,
                            const QList<GU_IMPORT> &listImports, const QByteArray &baRelocBlob, int *pnSections)
{
    // Collect the committed image regions inside [nImageBase, nImageBase+nImageSize)
    // and turn each into a section of the rebuilt PE.
    QList<GU_SECTION> listSecs;
    QList<XEmuMemoryManager::REGION> listRegions = pMemoryManager->getRegions();

    // Sections must start at or above the first SectionAlignment page: the PE headers own
    // RVA 0..0x1000, and the rebuilt headers replace them. A dumped section at VA 0 overlaps
    // the headers and the Windows loader rejects the whole image ("not a valid application").
    const quint64 nFirstSecRva = 0x1000;

    for (int i = 0; i < listRegions.size(); i++) {
        const XEmuMemoryManager::REGION &region = listRegions.at(i);

        if (region.state != XEmuMemoryManager::STATE_COMMIT) {
            continue;
        }

        quint64 nStart = region.nAddress;
        quint64 nEnd = qMin<quint64>(region.nAddress + region.nSize, nImageBase + nImageSize);
        if (nStart < nImageBase + nFirstSecRva) {
            nStart = nImageBase + nFirstSecRva;  // skip the header page
        }
        if (nStart >= nEnd) {
            continue;  // region is entirely headers / outside the image
        }

        GU_SECTION sec;
        sec.nRva = (quint32)(nStart - nImageBase);
        sec.nSize = (quint32)(nEnd - nStart);

        bool bOk = false;
        sec.baData = pMemoryManager->read(nStart, sec.nSize, &bOk);
        if (!bOk) {
            continue;
        }

        listSecs.append(sec);
    }

    if (listSecs.isEmpty()) {
        if (pnSections) {
            *pnSections = 0;
        }
        return QByteArray();
    }

    std::sort(listSecs.begin(), listSecs.end(), guSectionRvaLess);

    quint32 nDumpedVEnd = 0;
    for (int i = 0; i < listSecs.size(); i++) {
        nDumpedVEnd = qMax(nDumpedVEnd, listSecs.at(i).nRva + listSecs.at(i).nSize);
    }

    // Rebuild the import directory into a fresh section past the dumped image (PE32 dword
    // slots/thunks, PE32+ qword).
    quint32 nImpDirRva = 0;
    quint32 nImpDirSize = 0;
    if (!listImports.isEmpty()) {
        const quint32 nImpSecRva = alignUp32(nDumpedVEnd, 0x1000);
        QByteArray baImp = guBuildImportBlob(listImports, nImpSecRva, bIs64, &nImpDirRva, &nImpDirSize);
        if (!baImp.isEmpty()) {
            GU_SECTION impSec;
            impSec.nRva = nImpSecRva;
            impSec.nSize = (quint32)baImp.size();
            impSec.baData = baImp;
            listSecs.append(impSec);
            nDumpedVEnd = qMax(nDumpedVEnd, nImpSecRva + impSec.nSize);
        }
    }

    // Reconstructed base-relocation directory (from the two-base diff), in its own section.
    quint32 nRelocDirRva = 0;
    quint32 nRelocDirSize = 0;
    if (!baRelocBlob.isEmpty()) {
        const quint32 nRelocSecRva = alignUp32(nDumpedVEnd, 0x1000);
        GU_SECTION relocSec;
        relocSec.nRva = nRelocSecRva;
        relocSec.nSize = (quint32)baRelocBlob.size();
        relocSec.baData = baRelocBlob;
        listSecs.append(relocSec);
        nRelocDirRva = nRelocSecRva;
        nRelocDirSize = (quint32)baRelocBlob.size();
        nDumpedVEnd = qMax(nDumpedVEnd, nRelocSecRva + relocSec.nSize);
    }

    if (pnSections) {
        *pnSections = listSecs.size();
    }

    const int nSectCount = listSecs.size();
    const quint32 nHeaderBase = 0x40 + 4 + 20 + (bIs64 ? 0xF0 : 0xE0);
    const quint32 nRawBase = alignUp32(nHeaderBase + 0x28 * nSectCount, 0x200);

    quint32 nRawTotal = nRawBase;
    quint32 nMaxVEnd = 0;
    for (int i = 0; i < nSectCount; i++) {
        nRawTotal += alignUp32(listSecs.at(i).nSize, 0x200);
        nMaxVEnd = qMax(nMaxVEnd, listSecs.at(i).nRva + listSecs.at(i).nSize);
    }

    // Preserve the Subsystem and the DLL/EXE characteristic from the ORIGINAL in-memory PE
    // header. guBuildPE drops the header page (RVA 0..0x1000) as a section, but its bytes are
    // still mapped, so a packed DLL stays a DLL (IMAGE_FILE_DLL) and a console program keeps
    // its console subsystem. Fall back to a GUI executable if the in-memory header is not a
    // sane PE (some stubs zero it out).
    quint16 nCharacteristics = 0x022F;  // executable, large-address-aware (default)
    quint16 nSubsystem = 2;             // IMAGE_SUBSYSTEM_WINDOWS_GUI (default)
    // Original data directories captured from the in-memory header, carried over so the shell
    // finds the icon/version info (Resource) and the loader sees TLS/LoadConfig/exception/etc.
    quint32 nOrigDirRva[16] = {0};
    quint32 nOrigDirSize[16] = {0};
    int nOrigDirs = 0;
    const int nOrigDdOff = bIs64 ? 0x70 : 0x60;
    if (guReadMem(pMemoryManager, nImageBase, 2) == 0x5A4D) {
        quint32 nLfanew = (quint32)guReadMem(pMemoryManager, nImageBase + 0x3C, 4);
        if ((nLfanew >= 0x40) && (nLfanew < nFirstSecRva) && (guReadMem(pMemoryManager, nImageBase + nLfanew, 4) == 0x00004550)) {
            // Characteristics: COFF header + 18; Subsystem: OptionalHeader + 68 (same offset
            // for PE32 and PE32+, since the fields from +32 on coincide). Force
            // IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) so the result is always runnable/loadable.
            // The RELOCS_STRIPPED bit is decided below from whether we rebuilt a .reloc.
            nCharacteristics = (quint16)(guReadMem(pMemoryManager, nImageBase + nLfanew + 4 + 18, 2) | 0x0002);
            quint16 nOrigSub = (quint16)guReadMem(pMemoryManager, nImageBase + nLfanew + 24 + 68, 2);
            if (nOrigSub != 0) {
                nSubsystem = nOrigSub;
            }
            const quint64 nOhAddr = nImageBase + nLfanew + 24;
            nOrigDirs = (int)qMin<quint32>(16, (quint32)guReadMem(pMemoryManager, nOhAddr + (bIs64 ? 108 : 92), 4));
            for (int i = 0; i < nOrigDirs; i++) {
                nOrigDirRva[i] = (quint32)guReadMem(pMemoryManager, nOhAddr + nOrigDdOff + i * 8 + 0, 4);
                nOrigDirSize[i] = (quint32)guReadMem(pMemoryManager, nOhAddr + nOrigDdOff + i * 8 + 4, 4);
            }
        }
    }

    QByteArray baResult(nRawTotal, (char)0);
    char *p = baResult.data();

    wr16(p + 0, 0x5A4D);   // "MZ"
    wr32(p + 0x3C, 0x40);  // e_lfanew

    char *pe = p + 0x40;
    wr32(pe + 0, 0x00004550);  // "PE\0\0"

    // RELOCS_STRIPPED (0x0001): keep it OFF when we rebuilt a .reloc (the image can then load at
    // any base); set it when we have no reloc table (dump is only valid at the preferred base,
    // so mark it stripped and never apply the packer's leftover stub relocs).
    if (!baRelocBlob.isEmpty()) {
        nCharacteristics &= ~(quint16)0x0001;
    } else {
        nCharacteristics |= 0x0001;
    }

    char *fh = pe + 4;
    wr16(fh + 0, bIs64 ? 0x8664 : 0x014C);   // Machine
    wr16(fh + 2, (quint16)nSectCount);       // NumberOfSections
    wr16(fh + 16, bIs64 ? 0x00F0 : 0x00E0);  // SizeOfOptionalHeader
    wr16(fh + 18, nCharacteristics);         // Characteristics (preserved; EXECUTABLE forced, RELOCS_STRIPPED per reloc table)

    char *oh = fh + 20;
    wr16(oh + 0, bIs64 ? 0x020B : 0x010B);  // Magic (PE32 / PE32+)
    wr32(oh + 16, (quint32)nOEP);           // AddressOfEntryPoint

    // Data-directory[1] (Import Table) offset differs between PE32 (0x60) and PE32+ (0x70).
    const int nDataDirOff = bIs64 ? 0x70 : 0x60;

    if (!bIs64) {
        wr32(oh + 28, (quint32)nImageBase);  // ImageBase
        wr32(oh + 32, 0x1000);               // SectionAlignment
        wr32(oh + 36, 0x200);                // FileAlignment
        wr16(oh + 40, 5);                    // MajorOperatingSystemVersion
        wr16(oh + 48, 5);                    // MajorSubsystemVersion
        wr32(oh + 56, alignUp32(nMaxVEnd, 0x1000));  // SizeOfImage
        wr32(oh + 60, nRawBase);             // SizeOfHeaders
        wr16(oh + 68, nSubsystem);           // Subsystem (preserved from source)
        wr32(oh + 92, 16);                   // NumberOfRvaAndSizes
    } else {
        wr32(oh + 24, (quint32)nImageBase);          // ImageBase (low)
        wr32(oh + 28, (quint32)(nImageBase >> 32));  // ImageBase (high)
        wr32(oh + 32, 0x1000);
        wr32(oh + 36, 0x200);
        wr16(oh + 40, 5);
        wr16(oh + 48, 5);
        wr32(oh + 56, alignUp32(nMaxVEnd, 0x1000));
        wr32(oh + 60, nRawBase);
        wr16(oh + 68, nSubsystem);
        wr32(oh + 108, 16);  // NumberOfRvaAndSizes (PE32+)
    }

    // Restore the original data directories so the result behaves like the unpacked original:
    // Resource [2] (icon / version info / manifest), Debug [6], TLS [9], LoadConfig [10],
    // Exception [3], Bound/Delay imports, CLR, ... Only copy a directory whose RVA lands in a
    // section we actually dumped (else it would point at bytes we don't carry). Skip:
    //   [1] Import   -- rebuilt below;
    //   [4] Security -- its "RVA" is really a file offset to an authenticode blob, stripped;
    //   [5] BaseReloc-- the value here is the PACKER's stub reloc, not the original table
    //                   (which the packer already applied and discarded); the image is dumped
    //                   relocated to its preferred base and marked RELOCS_STRIPPED, so any
    //                   reloc directory would be wrong. Leave it zero.
    for (int i = 0; i < nOrigDirs; i++) {
        if ((i == 1) || (i == 4) || (i == 5) || (nOrigDirRva[i] == 0)) {
            continue;
        }
        bool bInSec = false;
        for (int s = 0; s < listSecs.size(); s++) {
            if ((nOrigDirRva[i] >= listSecs.at(s).nRva) && (nOrigDirRva[i] < listSecs.at(s).nRva + listSecs.at(s).nSize)) {
                bInSec = true;
                break;
            }
        }
        if (!bInSec) {
            continue;
        }
        wr32(oh + nDataDirOff + i * 8 + 0, nOrigDirRva[i]);
        wr32(oh + nDataDirOff + i * 8 + 4, nOrigDirSize[i]);
    }

    if (nImpDirRva != 0) {
        wr32(oh + nDataDirOff + 1 * 8 + 0, nImpDirRva);   // DataDirectory[1].VirtualAddress (Import)
        wr32(oh + nDataDirOff + 1 * 8 + 4, nImpDirSize);  // DataDirectory[1].Size
    }

    if (nRelocDirRva != 0) {
        wr32(oh + nDataDirOff + 5 * 8 + 0, nRelocDirRva);   // DataDirectory[5].VirtualAddress (Base Relocation)
        wr32(oh + nDataDirOff + 5 * 8 + 4, nRelocDirSize);  // DataDirectory[5].Size
    }

    char *sec = oh + (bIs64 ? 0xF0 : 0xE0);
    quint32 nRaw = nRawBase;
    for (int i = 0; i < nSectCount; i++) {
        const GU_SECTION &s = listSecs.at(i);
        quint32 nRsz = alignUp32(s.nSize, 0x200);

        char szName[9];
        snprintf(szName, sizeof(szName), ".sec%.2d", i);
        memcpy(sec, szName, qMin<size_t>(8, strlen(szName)));

        wr32(sec + 8, s.nSize);      // VirtualSize
        wr32(sec + 12, s.nRva);      // VirtualAddress
        wr32(sec + 16, nRsz);        // SizeOfRawData
        wr32(sec + 20, nRaw);        // PointerToRawData
        wr32(sec + 36, 0xE00000E0);  // Characteristics: code+data, RWX

        if ((qint64)nRaw + s.baData.size() <= baResult.size()) {
            memcpy(baResult.data() + nRaw, s.baData.constData(), s.baData.size());
        }

        nRaw += nRsz;
        sec += 0x28;
    }

    return baResult;
}

QByteArray XEmulUnpacker::_buildMachO(XEmuMemoryManager *pMemoryManager, quint64 nImageBase, quint64 nImageSize, quint64 nOepAbs, bool bIs64,
                                            quint32 nCpuType, quint32 nCpuSubtype, int *pnSegments)
{
    QList<GU_SEGMENT> listSegs;
    QList<XEmuMemoryManager::REGION> listRegions = pMemoryManager->getRegions();
    for (int i = 0; i < listRegions.size(); i++) {
        const XEmuMemoryManager::REGION &region = listRegions.at(i);
        if (region.state != XEmuMemoryManager::STATE_COMMIT) {
            continue;
        }
        if ((region.nAddress < nImageBase) || (region.nAddress >= nImageBase + nImageSize)) {
            continue;
        }
        GU_SEGMENT seg;
        seg.nAddr = region.nAddress;
        seg.nSize = qMin<quint64>(region.nSize, nImageBase + nImageSize - region.nAddress);
        bool bOk = false;
        seg.baData = pMemoryManager->read(region.nAddress, seg.nSize, &bOk);
        if (!bOk) {
            continue;
        }
        listSegs.append(seg);
    }

    if (pnSegments) {
        *pnSegments = listSegs.size();
    }
    if (listSegs.isEmpty()) {
        return QByteArray();
    }

    std::sort(listSegs.begin(), listSegs.end(), guSegmentAddrLess);

    // ARM64 uses ARM_THREAD_STATE64 (flavor 6, count 68, pc at u64 index 32); x86-64
    // uses x86_THREAD_STATE64 (flavor 4, count 42, rip at u64 index 16).
    const bool bArm = (nCpuType == 0x0100000C);
    const quint32 nThreadFlavor = bArm ? 6 : 4;
    const quint32 nThreadCount = bArm ? 68 : 42;
    const int nRegIndex = bArm ? 32 : 16;
    const quint32 nThreadCmdSize = 16 + nThreadCount * 4;

    const quint32 nSegCmd = bIs64 ? 0x19 : 0x1;         // LC_SEGMENT_64 / LC_SEGMENT
    const quint32 nSegCmdSize = bIs64 ? 72 : 56;        // no sections
    const quint32 nHdrSize = bIs64 ? 32 : 28;
    const int nSegCount = listSegs.size();

    quint32 nSizeOfCmds = (quint32)nSegCount * nSegCmdSize + nThreadCmdSize;
    quint32 nHeaders = alignUp32(nHdrSize + nSizeOfCmds, 0x1000);

    quint32 nRawTotal = nHeaders;
    for (int i = 0; i < nSegCount; i++) {
        nRawTotal += alignUp32((quint32)listSegs.at(i).nSize, 0x1000);
    }

    QByteArray baResult(nRawTotal, (char)0);
    char *p = baResult.data();

    wr32(p + 0, bIs64 ? 0xFEEDFACF : 0xFEEDFACE);  // magic
    wr32(p + 4, nCpuType);
    wr32(p + 8, nCpuSubtype);
    wr32(p + 12, 2);  // MH_EXECUTE
    wr32(p + 16, (quint32)(nSegCount + 1));
    wr32(p + 20, nSizeOfCmds);
    wr32(p + 24, 0x1);  // MH_NOUNDEFS

    char *lc = p + nHdrSize;
    quint32 nRaw = nHeaders;
    for (int i = 0; i < nSegCount; i++) {
        const GU_SEGMENT &s = listSegs.at(i);
        quint32 nFileSize = alignUp32((quint32)s.nSize, 0x1000);

        wr32(lc + 0, nSegCmd);
        wr32(lc + 4, nSegCmdSize);
        char szName[17];
        snprintf(szName, sizeof(szName), "__SEG%.2d", i);
        memcpy(lc + 8, szName, qMin<size_t>(16, strlen(szName)));
        if (bIs64) {
            wr64(lc + 24, s.nAddr);        // vmaddr
            wr64(lc + 32, nFileSize);      // vmsize
            wr64(lc + 40, nRaw);           // fileoff
            wr64(lc + 48, s.nSize);        // filesize
            wr32(lc + 56, 7);              // maxprot rwx
            wr32(lc + 60, 7);              // initprot rwx
            wr32(lc + 64, 0);              // nsects
            wr32(lc + 68, 0);              // flags
        } else {
            wr32(lc + 24, (quint32)s.nAddr);
            wr32(lc + 28, nFileSize);
            wr32(lc + 32, nRaw);
            wr32(lc + 36, (quint32)s.nSize);
            wr32(lc + 40, 7);
            wr32(lc + 44, 7);
            wr32(lc + 48, 0);
            wr32(lc + 52, 0);
        }

        if ((qint64)nRaw + s.baData.size() <= baResult.size()) {
            memcpy(baResult.data() + nRaw, s.baData.constData(), s.baData.size());
        }
        nRaw += nFileSize;
        lc += nSegCmdSize;
    }

    // LC_UNIXTHREAD with the recovered entry point.
    wr32(lc + 0, 5);  // LC_UNIXTHREAD
    wr32(lc + 4, nThreadCmdSize);
    wr32(lc + 8, nThreadFlavor);
    wr32(lc + 12, nThreadCount);
    wr64(lc + 16 + nRegIndex * 8, nOepAbs);  // rip / pc

    return baResult;
}

QByteArray XEmulUnpacker::_reconstructElfFromMemory(XEmuMemoryManager *pMemoryManager, quint64 nImageBase, quint64 *pnEntry, int *pnSegments)
{
    bool bOk = false;
    if ((pMemoryManager->readByte(nImageBase, &bOk) != 0x7F) || !bOk) {
        return QByteArray();  // no ELF header mapped here
    }
    if ((guReadMem(pMemoryManager, nImageBase + 1, 1) != 'E') || (guReadMem(pMemoryManager, nImageBase + 2, 1) != 'L') || (guReadMem(pMemoryManager, nImageBase + 3, 1) != 'F')) {
        return QByteArray();
    }

    bool bIs64 = (guReadMem(pMemoryManager, nImageBase + 4, 1) == 2);
    int nPtr = bIs64 ? 8 : 4;
    quint64 nEntry = guReadMem(pMemoryManager, nImageBase + 24, nPtr);
    quint64 nPhOff = guReadMem(pMemoryManager, nImageBase + (bIs64 ? 0x20 : 0x1C), nPtr);
    quint16 nPhEntSize = (quint16)guReadMem(pMemoryManager, nImageBase + (bIs64 ? 0x36 : 0x2A), 2);
    quint16 nPhNum = (quint16)guReadMem(pMemoryManager, nImageBase + (bIs64 ? 0x38 : 0x2C), 2);

    if ((nPhOff == 0) || (nPhNum == 0) || (nPhNum > 512) || (nPhEntSize < (bIs64 ? 56 : 32))) {
        return QByteArray();
    }

    struct SEG {
        quint64 nOffset;
        quint64 nVaddr;
        quint64 nFileSize;
    };
    QList<SEG> listSegs;
    quint64 nMinVaddr = ~0ull;
    quint64 nFileEnd = 0;

    for (int i = 0; i < nPhNum; i++) {
        XADDR nPh = nImageBase + nPhOff + (quint64)i * nPhEntSize;
        quint32 nType = (quint32)guReadMem(pMemoryManager, nPh, 4);
        if (nType != 1) {  // PT_LOAD
            continue;
        }

        SEG seg;
        if (bIs64) {
            seg.nOffset = guReadMem(pMemoryManager, nPh + 8, 8);
            seg.nVaddr = guReadMem(pMemoryManager, nPh + 16, 8);
            seg.nFileSize = guReadMem(pMemoryManager, nPh + 32, 8);
        } else {
            seg.nOffset = guReadMem(pMemoryManager, nPh + 4, 4);
            seg.nVaddr = guReadMem(pMemoryManager, nPh + 8, 4);
            seg.nFileSize = guReadMem(pMemoryManager, nPh + 16, 4);
        }

        listSegs.append(seg);
        nMinVaddr = qMin(nMinVaddr, seg.nVaddr);
        nFileEnd = qMax(nFileEnd, seg.nOffset + seg.nFileSize);
    }

    if (listSegs.isEmpty() || (nFileEnd == 0) || (nFileEnd > 0x20000000)) {
        return QByteArray();
    }

    // The first PT_LOAD is mapped at nImageBase, so load bias = base - its (aligned)
    // virtual address; every segment then lives at loadBias + p_vaddr in memory.
    quint64 nLoadBias = nImageBase - (nMinVaddr & ~(XEmuMemoryManager::N_PAGE_SIZE - 1));

    QByteArray baResult((int)nFileEnd, (char)0);
    for (int i = 0; i < listSegs.size(); i++) {
        const SEG &seg = listSegs.at(i);
        bool bSegOk = false;
        QByteArray baData = pMemoryManager->read(nLoadBias + seg.nVaddr, seg.nFileSize, &bSegOk);
        if (bSegOk && ((qint64)(seg.nOffset + (quint64)baData.size()) <= baResult.size())) {
            memcpy(baResult.data() + seg.nOffset, baData.constData(), baData.size());
        }
    }

    // Section headers are not resident in memory, so drop the references to them.
    char *p = baResult.data();
    if (bIs64) {
        memset(p + 0x28, 0, 8);  // e_shoff
        memset(p + 0x3C, 0, 2);  // e_shnum
        memset(p + 0x3E, 0, 2);  // e_shstrndx
    } else {
        memset(p + 0x20, 0, 4);
        memset(p + 0x30, 0, 2);
        memset(p + 0x32, 0, 2);
    }

    if (pnEntry) {
        *pnEntry = nEntry;
    }
    if (pnSegments) {
        *pnSegments = listSegs.size();
    }
    return baResult;
}

quint8 XEmulUnpacker::OEP_CONTEXT::prev8() const
{
    return (baPrevCode.size() >= 1) ? (quint8)(uchar)baPrevCode.at(0) : (quint8)0;
}

quint16 XEmulUnpacker::OEP_CONTEXT::prev16() const
{
    if (baPrevCode.size() < 2) {
        return 0;
    }
    const uchar *p = reinterpret_cast<const uchar *>(baPrevCode.constData());
    return (quint16)(p[0] | (p[1] << 8));
}

quint32 XEmulUnpacker::OEP_CONTEXT::prev32() const
{
    if (baPrevCode.size() < 4) {
        return 0;
    }
    const uchar *p = reinterpret_cast<const uchar *>(baPrevCode.constData());
    return (quint32)(p[0] | (p[1] << 8) | (p[2] << 16) | ((quint32)p[3] << 24));
}

bool XEmulUnpacker::OEP_CONTEXT::matchSignature(quint64 nAddress, const char *pszHexPattern) const
{
    if ((pMemoryManager == nullptr) || (pszHexPattern == nullptr)) {
        return false;
    }

    // Collapse the pattern to a nibble string (drop spaces).
    QByteArray baPat;
    for (const char *s = pszHexPattern; *s != '\0'; ++s) {
        if (*s != ' ') {
            baPat.append(*s);
        }
    }
    const int nNibbles = baPat.size();
    if (nNibbles == 0) {
        return false;
    }
    const int nBytes = (nNibbles + 1) / 2;

    bool bOk = false;
    QByteArray baMem = pMemoryManager->read(nAddress, (quint64)nBytes, &bOk);
    if (!bOk || (baMem.size() < nBytes)) {
        return false;
    }

    for (int i = 0; i < nNibbles; i++) {
        const char c = baPat.at(i);
        if (c == '.') {
            continue;  // wildcard nibble
        }
        int nVal;
        if ((c >= '0') && (c <= '9')) {
            nVal = c - '0';
        } else if ((c >= 'a') && (c <= 'f')) {
            nVal = 10 + (c - 'a');
        } else if ((c >= 'A') && (c <= 'F')) {
            nVal = 10 + (c - 'A');
        } else {
            return false;
        }
        const uchar nByte = (uchar)baMem.at(i / 2);
        const int nMemNibble = ((i % 2) == 0) ? (nByte >> 4) : (nByte & 0x0F);
        if (nMemNibble != nVal) {
            return false;
        }
    }
    return true;
}

bool XEmulUnpacker::matchOEP(const OEP_CONTEXT &ctx, const OPTIONS &options) const
{
    Q_UNUSED(ctx)
    Q_UNUSED(options)
    // Generic base: no packer-specific signature. OEP detection is done by the
    // write-then-execute / section-hop heuristic in unpack().
    return false;
}

quint64 XEmulUnpacker::recoverOepAtStop(XEmuMemoryManager *, quint64, quint64, quint64, quint64) const
{
    return 0;  // generic base: no stored-OEP recovery
}

QString XEmulUnpacker::getPackerName() const
{
    return QStringLiteral("generic");
}

XEmulUnpacker::OPTIONS XEmulUnpacker::getDefaultOptions() const
{
    return OPTIONS();
}

void XEmulUnpacker::setStopFlag(const std::atomic_bool *pStopFlag)
{
    m_pStopFlag = pStopFlag;
}

XEmulUnpacker::RESULT XEmulUnpacker::unpack(const QString &sFileName)
{
    return unpack(sFileName, getDefaultOptions());
}

XEmulUnpacker::RESULT XEmulUnpacker::unpack(const QString &sFileName, const OPTIONS &options)
{
    RESULT result;
    result.sReason = QStringLiteral("not started");

    // Peek the container format. ELF packer stubs (UPX/Linux) reconstruct the
    // original program inside a file descriptor and execve() it, rather than jumping
    // to an in-image OEP, so they need a different completion signal.
    bool bElf = false;
    bool bMachO = false;
    quint64 nInputEntry = 0;
    quint32 nMachCpuType = 0;
    quint32 nMachCpuSubtype = 0;
    {
        QFile file(sFileName);
        if (file.open(QIODevice::ReadOnly)) {
            QByteArray baHdr = file.read(64);
            const uchar *e = reinterpret_cast<const uchar *>(baHdr.constData());

            bElf = baHdr.startsWith(QByteArray("\x7f" "ELF", 4));
            if (bElf && (baHdr.size() >= 64)) {
                int nSz = (e[4] == 2) ? 8 : 4;
                for (int i = 0; i < nSz; i++) {
                    nInputEntry |= (quint64)e[24 + i] << (i * 8);
                }
            } else if (baHdr.size() >= 16) {
                quint32 nMagic = e[0] | (e[1] << 8) | (e[2] << 16) | ((quint32)e[3] << 24);
                // Thin Mach-O (little-endian header), 32- or 64-bit, or a fat wrapper.
                if ((nMagic == 0xFEEDFACE) || (nMagic == 0xFEEDFACF)) {
                    bMachO = true;
                    nMachCpuType = e[4] | (e[5] << 8) | (e[6] << 16) | ((quint32)e[7] << 24);
                    nMachCpuSubtype = e[8] | (e[9] << 8) | (e[10] << 16) | ((quint32)e[11] << 24);
                } else if ((nMagic == 0xBEBAFECA) || (nMagic == 0xCAFEBABE)) {
                    bMachO = true;  // universal binary; cputype filled in from the loaded slice below
                }
            }
            file.close();
        }
    }

    XEmuEmulator emu;
    XEmuEmulator::OPTIONS emuOpt;
    emuOpt.bLoadDependencies = options.bLoadDependencies;
    emuOpt.sSystemRoot = options.sSystemRoot;

    // Capture the emulated OS calls the stub makes -- Windows APIs (VirtualAlloc,
    // LoadLibraryA, GetProcAddress, ...) or Linux syscalls (mmap, mprotect, memfd,
    // execve, ...) -- so the caller can see what it did.
    if (options.bCaptureApiLog) {
        connect(&emu, &XEmuEmulator::infoMessage, this, GU_ApiLogFilter{&result.listApiLog, options.nMaxApiLog});
    }
    connect(&emu, &XEmuEmulator::errorMessage, this, &XEmulUnpacker::infoMessage);

    if (!emu.loadFile(sFileName, emuOpt)) {
        result.sReason = QStringLiteral("loadFile failed");
        return result;
    }
    if (!emu.isReady()) {
        result.sReason = QStringLiteral("emulator not ready");
        return result;
    }

    QList<XEmuFileFormat::MODULE> listModules = emu.getModules();
    if (listModules.isEmpty()) {
        result.sReason = QStringLiteral("no modules");
        return result;
    }

    const XEmuFileFormat::MODULE &mainModule = listModules.at(0);
    quint64 nImageBase = mainModule.nBaseAddress;
    quint64 nImageSize = mainModule.nImageSize;
    result.nImageBase = nImageBase;
    result.nImageSize = nImageSize;

    XEmuMemoryManager *pMM = emu.getMemoryManager();
    XEmuArch *pArch = emu.getArch();
    XEmuRegisters *pRegs = emu.getRegisters();

    // Entry-point region (the section the stub starts executing in).
    quint64 nStartPC = pArch->getPC(pRegs);
    XEmuMemoryManager::REGION epRegion;
    if (!pMM->findRegion(nStartPC, &epRegion)) {
        result.sReason = QStringLiteral("entry region not found");
        return result;
    }
    const quint64 nEpStart = epRegion.nAddress;
    const quint64 nEpEnd = epRegion.nAddress + epRegion.nSize;
    const quint64 nPageMask = ~(XEmuMemoryManager::N_PAGE_SIZE - 1);

    // Snapshot the original section layout (the committed image regions as they are before
    // the stub runs). The live memory regions fragment as pages get written/re-protected, so
    // classifying a PC by its *current* region would report spurious section changes; the OEP
    // heuristic must compare against this stable, pre-execution layout.
    QList<GU_SECRANGE> listSecRanges;
    {
        QList<XEmuMemoryManager::REGION> listInit = pMM->getRegions();
        for (int i = 0; i < listInit.size(); i++) {
            const XEmuMemoryManager::REGION &r = listInit.at(i);
            if (r.state != XEmuMemoryManager::STATE_COMMIT) {
                continue;
            }
            if ((r.nAddress + r.nSize <= nImageBase) || (r.nAddress >= nImageBase + nImageSize)) {
                continue;
            }
            GU_SECRANGE sr;
            sr.nStart = r.nAddress;
            sr.nEnd = r.nAddress + r.nSize;
            listSecRanges.append(sr);
        }
    }
    // Track pages written during the run (only those inside the main image matter), and the
    // IAT slots the stub fills with resolved-import pointers (for import reconstruction).
    QSet<quint64> setDirtyPages;
    QMap<quint64, quint64> mapIatSlots;  // in-image IAT slot (abs addr) -> emulated-API stub value
    const quint64 nStubBase = emu.getApiStubBase();
    const quint64 nStubLimit = emu.getApiStubLimit();
    const int nPtr = mainModule.bIs64 ? 8 : 4;  // IAT slot / thunk width
    pMM->setWriteCallback(GU_DirtyPageWatcher{&setDirtyPages, nImageBase, nImageSize, nPageMask, &mapIatSlots, nStubBase, nStubLimit, nPtr});

    emit infoMessage(tr("Running stub from 0x%1 (entry section 0x%2-0x%3)").arg(nStartPC, 0, 16).arg(nEpStart, 0, 16).arg(nEpEnd, 0, 16));

    qint64 nSteps = 0;
    bool bOep = false;
    quint64 nOepAbs = 0;

    // Deferred write-then-execute (see OPTIONS::nOepDeferTailSteps): a remembered first
    // write-then-execute candidate, kept while the run continues to prefer a later
    // packer-signature OEP (the multi-stage loader case).
    bool bWtePending = false;
    quint64 nWtePendingOep = 0;
    qint64 nWtePendingStep = 0;

    // Weak OEP fallback for in-place / single-section decompressors: the FIRST cross-page jump
    // into a dirty in-image page (the stub handing off to the decompressed original) -- but the
    // cross-*section* write-then-execute heuristic can't see it when the stub restores the image
    // at its own VAs (same section). Recorded, never breaks; used ONLY if the run ends (halt /
    // clean process-exit) with no OEP detected. Working packers always fire a stronger heuristic
    // first, so they never reach this fallback -> no regression risk.
    quint64 nWeakOep = 0;
    bool bTlsCallbacksRun = false;

    // EP-redirect fallback for tiny in-place crypters and "stored" stubs whose entire
    // decrypt+hand-off runs in fewer than nOepMinStubSteps instructions (so the gated strong/weak
    // heuristics never arm) AND whose hand-off is structurally invisible to the page-crossing
    // checkpoints -- an intra-page or non-dirty transfer BACK to the original entry sitting at or
    // before the packer EP (e.g. "mov ebx,0x401000; jmp ebx" or "jmp [ebp-0xC]" landing on the
    // image/section start). Recorded every step (not just on page crossings); the nNext<=nStartPC
    // term short-circuits normal forward flow so it is cheap. Consumed at run-end BELOW nWeakOep,
    // only when no stronger heuristic fired -- working packers break earlier, so no regression.
    quint64 nEpRedirectOep = 0;

    // Address of the last *real* instruction executed (not an emulated-API trampoline).
    // Used to tell where an API was called from, so an OEP hand-off that arrives as a
    // return from an emulated API can be recognised (see the "api-return" check below).
    quint64 nLastRealPC = nStartPC;

    // Initial stack pointer. A genuine OEP hand-off happens with the stack balanced back
    // to this value (the stub has popad/popf'd its saved context); the per-packer
    // signatures in matchOEP() key on nSpDelta == 0.
    const qint64 nInitSP = (qint64)pArch->getStackPointer(pRegs);

    // OEP detection: the packer stub decompresses the original image and then makes a
    // *cross-section* control transfer into memory it has written (the reconstructed
    // code). Same-section jumps -- including a self-modifying stub re-executing its own
    // just-decrypted page -- are not OEP transfers and are ignored, which is what lets a
    // stub that lives in the same section as the OEP (e.g. NSpack 2.x, whose entry point
    // is a lone jmp thunk sharing the OEP's section) be handled correctly. A transfer is
    // only taken as the OEP once the stub has done real work (nOepMinStubSteps): multi-
    // stage stubs jump into a freshly written *next stage* within the first handful of
    // instructions, long before anything is actually decompressed.
    Q_UNUSED(nEpStart)
    Q_UNUSED(nEpEnd)
    quint64 nPrevPage = ~0ull;
    int nPrevSection = -2;  // -2 = uninitialised, -1 = outside all snapshot sections
    const int nStartSection = guSectionOf(listSecRanges, nStartPC);

    // --- TLS callbacks: real Windows runs these BEFORE the entry point ----------------------
    // Some packers (ASDPack) do ALL their unpacking inside a TLS callback; the emulator does not
    // run TLS callbacks on its own, so without this the stub never decompresses (it faults on the
    // still-packed entry page). Build a tiny trampoline that invokes each DataDirectory[9]
    // callback as callback(hInstance, DLL_PROCESS_ATTACH, NULL) and then jumps to the real entry,
    // and start execution there instead of at the entry. The trampoline lives outside the image
    // (its transfers are section -1, never mistaken for an OEP hand-off) and the whole sequence
    // runs inside the OEP-detection loop below, so the eventual hand-off is detected normally.
    // 32-bit only (stdcall callbacks clean their own 3 args via `ret 0xC`); 64-bit TLS is rare.
    if (!bElf && !bMachO && !mainModule.bIs64 && (nStartPC >= nImageBase) && (nStartPC < nImageBase + nImageSize)) {
        const quint64 nLfanew = guReadMem(pMM, nImageBase + 0x3C, 4);
        const quint64 nOpt = nImageBase + nLfanew + 0x18;
        const quint32 nTlsRva = (quint32)guReadMem(pMM, nOpt + 0x60 + 9 * 8, 4);  // DataDirectory[9] (PE32)
        if ((nTlsRva != 0) && (nTlsRva < nImageSize)) {
            const quint64 nCbArray = guReadMem(pMM, nImageBase + nTlsRva + 0x0C, 4);  // AddressOfCallBacks (VA)
            QList<quint32> listCb;
            if ((nCbArray >= nImageBase) && (nCbArray < nImageBase + nImageSize)) {
                for (int i = 0; i < 64; i++) {
                    quint32 nCb = (quint32)guReadMem(pMM, nCbArray + (quint64)i * 4, 4);
                    if (nCb == 0) break;
                    if ((nCb < nImageBase) || (nCb >= nImageBase + nImageSize)) break;  // guard bogus pointer
                    listCb.append(nCb);
                }
            }
            if (!listCb.isEmpty()) {
                QByteArray baThunk;
                auto guEmit32 = [&](quint32 v) { for (int k = 0; k < 4; k++) baThunk.append((char)((v >> (k * 8)) & 0xFF)); };
                for (const quint32 nCb : listCb) {
                    baThunk.append((char)0x6A); baThunk.append((char)0x00);      // push 0            (reserved)
                    baThunk.append((char)0x6A); baThunk.append((char)0x01);      // push 1            (DLL_PROCESS_ATTACH)
                    baThunk.append((char)0x68); guEmit32((quint32)nImageBase);   // push imagebase    (hInstance)
                    baThunk.append((char)0xB8); guEmit32(nCb);                   // mov eax, callback
                    baThunk.append((char)0xFF); baThunk.append((char)0xD0);      // call eax
                }
                baThunk.append((char)0xB8); guEmit32((quint32)nStartPC);         // mov eax, entry
                baThunk.append((char)0xFF); baThunk.append((char)0xE0);          // jmp eax
                XADDR nThunk = pMM->allocate(0, 0x1000, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("tls-thunk"));
                if (nThunk != 0) {
                    pMM->write(nThunk, baThunk);
                    pArch->setPC(pRegs, nThunk);
                    bTlsCallbacksRun = true;
                    emit infoMessage(tr("TLS: running %1 callback(s) before entry (thunk @ 0x%2)").arg(listCb.size()).arg(nThunk, 0, 16));
                }
            }
        }
    }

    for (; nSteps < options.nMaxSteps; nSteps++) {
        // Cooperative cancellation (polled cheaply, not every single instruction).
        if (m_pStopFlag && ((nSteps & 0x3FFF) == 0) && m_pStopFlag->load(std::memory_order_relaxed)) {
            result.sReason = QStringLiteral("cancelled after %1 steps").arg(nSteps);
            break;
        }

        quint64 nPC = pArch->getPC(pRegs);
        quint64 nPage = nPC & nPageMask;

        // Classify by the stable snapshot section only when execution crosses a page
        // boundary (sectionOf is a short linear scan; per-instruction would be wasteful).
        if (nPage != nPrevPage) {
            int nSection = guSectionOf(listSecRanges, nPC);

            bool bInImage = (nPC >= nImageBase) && (nPC < nImageBase + nImageSize);
            // A transfer between two *valid image sections* only. Excursions to section -1
            // (stack, heap, emulated API thunks -- anything outside the snapshot sections)
            // and the return from them are not OEP hand-offs; requiring both endpoints to be
            // real sections is what stops a self-modifying stub that calls out and comes back
            // from firing on every return into its own (now dirty) section.
            bool bCrossSection = (nPrevSection >= 0) && (nSection >= 0) && (nSection != nPrevSection);
            bool bDirtyTarget = setDirtyPages.contains(nPage);

            if (!bElf && (nSteps >= options.nOepMinStubSteps) && bInImage && bCrossSection) {
                if (bDirtyTarget && options.bDetectWriteExec) {
                    if (options.nOepDeferTailSteps > 0) {
                        // Multi-stage loader: remember the first candidate but keep running so a
                        // packer-signature matchOEP() (a later real hand-off) can win. Only the
                        // FIRST candidate is remembered -- later cross-section jumps the real
                        // program itself makes must not overwrite it.
                        if (!bWtePending) {
                            bWtePending = true;
                            nWtePendingOep = nPC;
                            nWtePendingStep = nSteps;
                        }
                    } else {
                        // Cross-section transfer into written memory: the OEP hand-off.
                        bOep = true;
                        nOepAbs = nPC;
                        result.sMethod = QStringLiteral("write-then-execute");
                        break;
                    }
                }
                if (!bDirtyTarget && options.bDetectSectionHop && (nSection != nStartSection)) {
                    // Fallback (off by default): a cross-section transfer into raw memory.
                    bOep = true;
                    nOepAbs = nPC;
                    result.sMethod = QStringLiteral("section-hop");
                    break;
                }
            }

            nPrevSection = nSection;
            nPrevPage = nPage;
        }

        // Deferred write-then-execute: a remembered candidate whose grace window has elapsed
        // with no packer-signature hand-off is taken as the OEP (single-stage stub -- its first
        // write-then-execute jump already was the real entry).
        if (bWtePending && !bOep && ((nSteps - nWtePendingStep) >= options.nOepDeferTailSteps)) {
            bOep = true;
            nOepAbs = nWtePendingOep;
            result.sMethod = QStringLiteral("write-then-execute");
            break;
        }

        if ((options.nProgressInterval > 0) && (nSteps > 0) && ((nSteps % options.nProgressInterval) == 0)) {
            emit progress(nSteps, nPC, setDirtyPages.size());
        }

        XEmuArch::STEP_INFO si = emu.step();

        if (si.result == XEmuArch::STEP_HALT) {
            // The stub ran the decompressed program to a clean exit (ExitProcess) without a
            // strong OEP hand-off being detected -- an in-place / single-section decompressor.
            // Fall back to the weak candidate (first cross-page jump into written memory).
            if (!bOep && (nWeakOep != 0)) {
                bOep = true;
                nOepAbs = nWeakOep;
                result.sMethod = QStringLiteral("in-place hand-off");
            }
            if (!bOep) {
                // Per-packer stored-OEP recovery (priority weak-OEP > recovery > ep-redirect). nPack's
                // bcb stub faults/halts in its aPLib depacker before the C3-ret matchOEP fires; the
                // real OEP is stored as an absolute dword its `push [P]; ret` tail would have used.
                const int nEntrySec = guSectionOf(listSecRanges, nStartPC);
                quint64 nScanStart = nImageBase, nScanEnd = nImageBase + nImageSize;
                if (nEntrySec >= 0) { nScanStart = listSecRanges.at(nEntrySec).nStart; nScanEnd = listSecRanges.at(nEntrySec).nEnd; }
                const quint64 nRec = recoverOepAtStop(pMM, nScanStart, nScanEnd, nImageBase, nImageSize);
                if (nRec != 0) {
                    const int nRecSec = guSectionOf(listSecRanges, nRec);
                    if ((nRec >= nImageBase) && (nRec < nImageBase + nImageSize) && (nRecSec >= 0) &&
                        (nRecSec != nEntrySec) && setDirtyPages.contains(nRec & nPageMask)) {
                        bOep = true;
                        nOepAbs = nRec;
                        result.sMethod = getPackerName() + QStringLiteral(" OEP-slot recovery");
                    }
                }
            }
            if (!bOep && (nEpRedirectOep != 0)) {
                // Tiny in-place crypter / EP-redirect stub whose hand-off was intra-page or into a
                // non-dirty page (so nWeakOep never saw it): take the back-jump to the original
                // entry recorded above.
                bOep = true;
                nOepAbs = nEpRedirectOep;
                result.sMethod = QStringLiteral("ep-redirect hand-off");
            }
            if (!bOep && bTlsCallbacksRun && (si.sText == QStringLiteral("process-exit")) &&
                (getPackerName() == QStringLiteral("ASPack")) && (nStartSection >= 0) &&
                (nStartPC >= nImageBase) && (nStartPC < nImageBase + nImageSize) &&
                !setDirtyPages.isEmpty() && (nStartPC != 0)) {
                // ASDPack samples can complete all unpacking inside a TLS callback and
                // terminate there via ExitProcess. The true OEP is the original entry in that
                // case even if no conventional transfer heuristic fired.
                bOep = true;
                nOepAbs = nStartPC;
                result.sMethod = QStringLiteral("ASPack TLS callback exit");
            }
            if (!bElf && !bMachO && !bOep && !bWtePending && setDirtyPages.isEmpty() &&
                       (nStartPC >= nImageBase) && (nStartPC < nImageBase + nImageSize) &&
                       (si.nAddress >= nStubBase) && (si.nAddress < nStubLimit)) {
                // EP-is-OEP "stored"/passthrough output (cexe, 20to4, UPolyX on an incompressible
                // input): the mapped image was NEVER self-modified (no in-image page went dirty)
                // yet the program ran to a clean emulated terminate (ExitProcess-style trampoline
                // in the API stub arena). The on-disk image already IS the original program; its
                // entry point is the OEP -- dump as-is.
                bOep = true;
                nOepAbs = nStartPC;
                result.sMethod = QStringLiteral("ep-is-oep (stored)");
            }
            result.sReason = QStringLiteral("halt at 0x%1").arg(si.nAddress, 0, 16);
            break;
        }
        if (si.result == XEmuArch::STEP_FAULT) {
            // In-place restorers (mkfpack/aPLib) reach the real OEP by jumping from an allocated
            // loader buffer (snapshot section -1, so the strong cross-section heuristic never
            // fires) into the restored, dirty image -- recorded as nWeakOep/nEpRedirectOep. The
            // decompressed program then runs and, lacking a real thread-exit environment, its CRT
            // eventually returns into the stale loader entry, which re-runs the depacker over the
            // already-restored image and faults. The OEP was already reached and the image is
            // intact, so consume the recorded candidate exactly as the clean-exit path does.
            // A remembered deferred write-then-execute candidate (bWtePending) is the strongest
            // signal and takes priority -- matching the end-of-run consume order below, so a family
            // that already reached its deferred OEP before faulting (MPress) keeps that exact OEP.
            if (!bOep && bWtePending) {
                bOep = true;
                nOepAbs = nWtePendingOep;
                result.sMethod = QStringLiteral("write-then-execute");
            } else if (!bOep && (nWeakOep != 0)) {
                bOep = true;
                nOepAbs = nWeakOep;
                result.sMethod = QStringLiteral("in-place hand-off (post-OEP fault)");
            }
            if (!bOep) {
                // Per-packer stored-OEP recovery (nPack bcb: the aPLib depacker faults before the
                // C3-ret matchOEP hand-off; the real OEP is a stored absolute dword). Priority sits
                // below weak-OEP and above ep-redirect, matching the halt path.
                const int nEntrySec = guSectionOf(listSecRanges, nStartPC);
                quint64 nScanStart = nImageBase, nScanEnd = nImageBase + nImageSize;
                if (nEntrySec >= 0) { nScanStart = listSecRanges.at(nEntrySec).nStart; nScanEnd = listSecRanges.at(nEntrySec).nEnd; }
                const quint64 nRec = recoverOepAtStop(pMM, nScanStart, nScanEnd, nImageBase, nImageSize);
                if (nRec != 0) {
                    const int nRecSec = guSectionOf(listSecRanges, nRec);
                    if ((nRec >= nImageBase) && (nRec < nImageBase + nImageSize) && (nRecSec >= 0) &&
                        (nRecSec != nEntrySec) && setDirtyPages.contains(nRec & nPageMask)) {
                        bOep = true;
                        nOepAbs = nRec;
                        result.sMethod = getPackerName() + QStringLiteral(" OEP-slot recovery");
                    }
                }
            }
            if (!bOep && (nEpRedirectOep != 0)) {
                bOep = true;
                nOepAbs = nEpRedirectOep;
                result.sMethod = QStringLiteral("ep-redirect hand-off (post-OEP fault)");
            }
            result.sReason = QStringLiteral("fault at 0x%1: %2").arg(si.nAddress, 0, 16).arg(si.sComment);
            break;
        }
        if (si.result == XEmuArch::STEP_UNIMPLEMENTED) {
            result.sReason = QStringLiteral("unimplemented opcode at 0x%1: %2").arg(si.nAddress, 0, 16).arg(si.sText);
            break;
        }

        // Per-packer OEP signature (subclasses only). Inspect the instruction that just
        // retired (si == "prev", the stub's terminating instruction) and where control
        // landed (the new PC == "curr", the OEP candidate). Only meaningful when the jump
        // left the current page; a subclass's matchOEP() then keys on the exact opcode,
        // the balanced stack and the jump direction. The generic base returns false here,
        // so it stays driven by the write-then-execute heuristic above.
        if (!bElf) {
            const quint64 nInstrAddr = si.nAddress;
            const quint64 nInstrPage = nInstrAddr & nPageMask;
            const quint64 nNext = pArch->getPC(pRegs);
            const quint64 nNextPage = nNext & nPageMask;

            // EP-redirect hand-off (tiny in-place crypters / stored stubs). A TAKEN transfer whose
            // target is at or before the original entry and inside a real image section -- the
            // classic "jump back to the OEP at the image/section start". Evaluated EVERY step (the
            // hand-off is frequently intra-page, so the page-crossing block below never sees it).
            // nNext <= nStartPC short-circuits normal forward flow -> cheap. First-wins, stack near
            // balanced, target not the sequential fall-through. Recorded only; consumed at halt.
            if ((nEpRedirectOep == 0) && (nNext <= nStartPC) && (nNext >= nImageBase) &&
                (nNext != nInstrAddr + si.nLength) && (guSectionOf(listSecRanges, nNext) >= 0)) {
                const qint64 nSpNow = (qint64)pArch->getStackPointer(pRegs) - nInitSP;
                if ((nSpNow >= -0x40) && (nSpNow <= 0x40)) {
                    nEpRedirectOep = nNext;
                }
            }

            if (nInstrPage != nNextPage) {
                OEP_CONTEXT ctx;
                ctx.pMemoryManager = pMM;
                ctx.nPrevAddress = nInstrAddr;
                ctx.nPrevSize = si.nLength;
                ctx.baPrevCode = pMM->read(nInstrAddr, si.nLength ? qMin<quint32>(si.nLength, 16) : 16);
                ctx.nCurrAddress = nNext;
                ctx.nSpDelta = (qint64)pArch->getStackPointer(pRegs) - nInitSP;
                ctx.bJumpFromHigh = (nInstrPage > nNextPage);
                ctx.bJumpToHigh = (nInstrPage < nNextPage);
                ctx.bJumpFromHeader = (nInstrPage == nImageBase);
                ctx.bPrevIsImage = (nInstrAddr >= nImageBase) && (nInstrAddr < nImageBase + nImageSize);
                ctx.bCurrIsImage = (nNext >= nImageBase) && (nNext < nImageBase + nImageSize);
                ctx.bDirtyTarget = setDirtyPages.contains(nNextPage);
                ctx.nSteps = nSteps;
                ctx.nImageBase = nImageBase;
                ctx.nImageSize = nImageSize;

                // Heap = a committed region outside the image that is not the stack region.
                ctx.bPrevIsHeap = false;
                if (!ctx.bPrevIsImage) {
                    XEmuMemoryManager::REGION rPrev;
                    if (pMM->findRegion(nInstrAddr, &rPrev) && (rPrev.state == XEmuMemoryManager::STATE_COMMIT)) {
                        XEmuMemoryManager::REGION rStack;
                        if (pMM->findRegion((quint64)nInitSP - 1, &rStack)) {
                            ctx.bPrevIsHeap = (rPrev.nAddress != rStack.nAddress);
                        } else {
                            ctx.bPrevIsHeap = true;
                        }
                    }
                }

                if (matchOEP(ctx, options)) {
                    bOep = true;
                    nOepAbs = nNext;
                    result.sMethod = getPackerName() + QStringLiteral(" signature");
                    break;
                }

                // Weak OEP candidate: the first cross-page, CROSS-SECTION jump into a dirty, in-image
                // page with the stack near-balanced -- i.e. the sub-nOepMinStubSteps analog of the
                // strong write-then-execute heuristic, for tiny crypters (PolyEnE, Stone's, dePack)
                // whose stub lives in a section separate from the OEP and hands off in far fewer than
                // 5000 steps. The cross-section requirement is essential: without it this fires on a
                // self-decrypting stub re-executing its OWN just-decrypted page (PE Pack: the PEPACK!!
                // stub decrypts itself and the false hit lands at 0x307d instead of the real OEP in
                // .text). Same-section / backward hand-offs are handled by nEpRedirectOep instead.
                // No gate; never breaks the run -- consumed ONLY at end-of-run when no stronger
                // heuristic fired, which a working multi-stage packer never reaches.
                const int nWeakSec = guSectionOf(listSecRanges, nNext);
                if ((nWeakOep == 0) && ctx.bCurrIsImage && ctx.bDirtyTarget &&
                    (nWeakSec >= 0) && (nWeakSec != nStartSection) &&
                    (ctx.nSpDelta >= -0x40) && (ctx.nSpDelta <= 0x40)) {
                    nWeakOep = nNext;
                }
            }
        }

        // OEP via emulated-API return. A loader that runs its final stage from allocated
        // memory (Petite frees its scratch with VirtualFree; others VirtualProtect and
        // return) reaches the OEP by *returning from* an emulated API into the rebuilt
        // image. The transfer's source is the API stub, so neither the cross-section nor
        // the packer-signature heuristic sees it. Recognise it precisely: an emulated-API
        // step whose caller was OUTSIDE the main image and whose return lands on a written
        // page INSIDE the main image, after the stub has done real work. The
        // caller-outside-image gate keeps image-resident stubs (UPX, ...) that merely
        // VirtualProtect their own sections from matching.
        if (!bElf && (si.sText == QStringLiteral("emulated-api")) && (nSteps >= options.nOepMinStubSteps)) {
            const quint64 nRet = pArch->getPC(pRegs);
            const quint64 nRetPage = nRet & nPageMask;
            const bool bRetInImage = (nRet >= nImageBase) && (nRet < nImageBase + nImageSize);
            const bool bCallerInImage = (nLastRealPC >= nImageBase) && (nLastRealPC < nImageBase + nImageSize);

            if (bRetInImage && !bCallerInImage && setDirtyPages.contains(nRetPage)) {
                bOep = true;
                nOepAbs = nRet;
                result.sMethod = QStringLiteral("api-return");
                break;
            }
        }

        // Remember the last real (non-trampoline) instruction so the next API return can
        // tell whether the call came from the image or from allocated loader memory.
        if (si.nLength > 0) {
            nLastRealPC = si.nAddress;
        }
    }

    // Detach the write hook before the memory manager outlives this scope's captures.
    pMM->setWriteCallback(XEmuMemoryManager::MEM_CALLBACK());

    result.nSteps = nSteps;

    // ELF / execve style: the stub reconstructed the original program inside a file
    // descriptor and handed it back via execve. That descriptor's bytes *are* the
    // unpacked ELF -- no memory dump or PE rebuild needed.
    QByteArray baReplacement;
    if (emu.getReplacementImage(&baReplacement) && !baReplacement.isEmpty()) {
        result.baPE = baReplacement;
        result.sMethod = QStringLiteral("execve-image");
        result.bSuccess = true;

        // Parse the ELF header for the entry point and program-header count.
        if ((baReplacement.size() >= 64) && baReplacement.startsWith(QByteArray("\x7f" "ELF", 4))) {
            const uchar *p = reinterpret_cast<const uchar *>(baReplacement.constData());
            bool bIs64Elf = (p[4] == 2);
            quint64 nEntry = 0;
            if (bIs64Elf) {
                for (int i = 0; i < 8; i++) {
                    nEntry |= (quint64)p[24 + i] << (i * 8);
                }
                result.nSections = p[56] | (p[57] << 8);  // e_phnum
            } else {
                for (int i = 0; i < 4; i++) {
                    nEntry |= (quint64)p[24 + i] << (i * 8);
                }
                result.nSections = p[44] | (p[45] << 8);
            }
            result.nOEP = nEntry;
            emit oepDetected(result.nOEP, result.sMethod);
        }

        result.sReason = QStringLiteral("unpacked ELF reconstructed via execve (%1 bytes, entry 0x%2) after %3 steps")
                             .arg(baReplacement.size())
                             .arg(result.nOEP, 0, 16)
                             .arg(nSteps);
        return result;
    }

    // ELF, in-memory style: a dynamically-linked target decompresses its own program
    // headers and segments at the image base and then hands off to ld.so (which we
    // cannot run without a filesystem). Rebuild the original ELF from that in-memory
    // layout. Validate by requiring the recovered entry point to differ from the
    // packed file's (i.e. decompression actually happened).
    if (bElf) {
        quint64 nMemEntry = 0;
        int nSegs = 0;
        QByteArray baElf = _reconstructElfFromMemory(pMM, nImageBase, &nMemEntry, &nSegs);

        if (!baElf.isEmpty() && (nMemEntry != 0) && (nMemEntry != nInputEntry)) {
            result.baPE = baElf;
            result.sMethod = QStringLiteral("elf-memory-image");
            result.nSections = nSegs;
            result.nOEP = nMemEntry;
            result.bSuccess = true;
            emit oepDetected(result.nOEP, result.sMethod);
            result.sReason = QStringLiteral("unpacked ELF rebuilt from memory (%1 bytes, entry 0x%2, %3 segment(s)) after %4 steps")
                                 .arg(baElf.size())
                                 .arg(result.nOEP, 0, 16)
                                 .arg(nSegs)
                                 .arg(nSteps);
            return result;
        }
    }

    // A remembered deferred candidate that the run ended on (halt / fault / step limit) before
    // any packer signature fired: take it. The stub reached its (single-stage) hand-off; the
    // subsequent halt was the unpacked program itself running to ExitProcess.
    if (!bOep && bWtePending && !bElf && !bMachO) {
        bOep = true;
        nOepAbs = nWtePendingOep;
        result.sMethod = QStringLiteral("write-then-execute");
    }

    if (!bOep) {
        if (result.sReason == QStringLiteral("not started")) {
            result.sReason = (nSteps >= options.nMaxSteps) ? QStringLiteral("step limit reached, no OEP") : QStringLiteral("stopped before OEP");
        }
        return result;
    }

    result.nOEP = nOepAbs - nImageBase;
    emit oepDetected(result.nOEP, result.sMethod);

    if (bMachO) {
        // Default the CPU type for a universal-binary input from the loaded slice.
        quint32 nCpuType = nMachCpuType ? nMachCpuType : (mainModule.bIs64 ? 0x01000007u : 0x00000007u);
        result.baPE = _buildMachO(pMM, nImageBase, nImageSize, nOepAbs, mainModule.bIs64, nCpuType, nMachCpuSubtype, &result.nSections);
    } else {
        // Also scan the FINAL image for IAT slots: packers that preserve the original import
        // directory get their IAT patched at process setup (before the write watcher was
        // installed), so the watcher never saw those writes. Every resolved-import pointer is
        // a stub-arena value; sweeping the committed image dwords recovers them regardless of
        // when they were written. The high, DLL-like arena base (XEmuWinApi::init) makes a
        // stub-range value unambiguously a real import, so no density/run filter is needed;
        // the listImports pass below still reconciles each candidate against live memory.
        if (nStubLimit > nStubBase) {
            const QList<XEmuMemoryManager::REGION> listImgRegions = pMM->getRegions();
            for (int ri = 0; ri < listImgRegions.size(); ri++) {
                const XEmuMemoryManager::REGION &rg = listImgRegions.at(ri);
                if (rg.state != XEmuMemoryManager::STATE_COMMIT) {
                    continue;
                }
                quint64 a0 = qMax<quint64>(rg.nAddress, nImageBase);
                quint64 a1 = qMin<quint64>(rg.nAddress + rg.nSize, nImageBase + nImageSize);
                a0 = (a0 + 3) & ~(quint64)3;  // dword-align (minimum IAT-slot alignment)
                if (a0 >= a1) {
                    continue;
                }
                bool bReadOk = false;
                QByteArray baRegion = pMM->read(a0, a1 - a0, &bReadOk);
                if (!bReadOk) {
                    continue;
                }
                const uchar *pr = (const uchar *)baRegion.constData();
                // Step by 4 (a PE32+ thunk array can be dword-aligned) but read a full pointer:
                // a straddling read across two 8-byte slots has its high bits set and falls out
                // of the stub range, so only genuine slots are recorded.
                for (int off = 0; off + nPtr <= baRegion.size(); off += 4) {
                    quint64 v = 0;
                    for (int k = 0; k < nPtr; k++) {
                        v |= (quint64)pr[off + k] << (k * 8);
                    }
                    if ((v >= nStubBase) && (v < nStubLimit)) {
                        mapIatSlots.insert(a0 + (quint64)off, v);
                    }
                }
            }
        }

        // Turn the recorded IAT slots (in-image addresses the stub filled with resolved-API
        // trampolines) into a reconstructed import table so the dumped exe is runnable: the
        // real loader re-resolves each FirstThunk from the rebuilt names. Without this the
        // IAT still points at the emulator's internal stub arena and the exe crashes on its
        // first API call.
        QList<GU_IMPORT> listImports;
        for (QMap<quint64, quint64>::const_iterator it = mapIatSlots.constBegin(); options.bReconstructImports && (it != mapIatSlots.constEnd()); ++it) {
            const quint64 nSlotAddr = it.key();
            // Skip the header page: guBuildPE drops RVA < 0x1000 (the rebuilt headers own it),
            // so a FirstThunk there would point into no emitted section (and the loader would
            // write the resolved address into the read-only header region).
            if ((nSlotAddr < nImageBase + 0x1000) || (nSlotAddr >= nImageBase + nImageSize)) {
                continue;
            }
            // Authoritative final-state check: the slot must STILL hold a stub value in the
            // dumped image. The write-watcher is last-write-wins, so a transient stub pointer
            // the stub later overwrote with real code/data could linger in mapIatSlots; re-read
            // live memory so such a slot never becomes a phantom import (whose FirstThunk the
            // loader would write over, corrupting that code/data).
            const quint64 nLive = guReadMem(pMM, nSlotAddr, nPtr);
            if ((nLive < nStubBase) || (nLive >= nStubLimit)) {
                continue;
            }
            GU_IMPORT imp;
            imp.nSlotRva = (quint32)(nSlotAddr - nImageBase);
            imp.nOrdinal = -1;
            if (!emu.resolveImportStub(nLive, &imp.sLibrary, &imp.sFunction, &imp.nOrdinal)) {
                continue;  // not a named/modelled import (e.g. an internal trampoline)
            }
            if (imp.sLibrary.isEmpty()) {
                continue;
            }
            // Route by-ordinal on the ORDINAL, not on sFunction emptiness: XEmuPE::getImports
            // stringifies a by-ordinal import's ordinal into sFunction (a decimal like "115"),
            // and the GetProcAddress-by-ordinal path stores "#115" -- both NON-empty. Emitting
            // them as by-name would write a bogus IMAGE_IMPORT_BY_NAME the real loader cannot
            // resolve. Clearing sFunction makes guBuildImportBlob emit an ordinal thunk
            // (IMAGE_ORDINAL_FLAG32 | ordinal). (Mirrors _collectImportsFor in xemuwindows.cpp,
            // where by-name imports carry nOrdinal 0/-1 and by-ordinal imports carry >= 1.)
            if (imp.nOrdinal >= 1) {
                imp.sFunction.clear();
            } else if (imp.sFunction.isEmpty()) {
                continue;  // neither a usable name nor an ordinal: would emit a null thunk mid-INT
            }
            listImports.append(imp);
        }
        result.nImports = listImports.size();

        // Reconstruct base relocations for a relocatable image (mostly DLLs): run the stub a
        // second time at a different base and diff the two unpacked images -- every field that
        // moved by exactly the base delta is an absolute address that needs a fixup. Rebuild a
        // real .reloc so the output loads at any base. Non-relocatable images stay
        // RELOCS_STRIPPED (a preferred-base-only dump, which is correct for them).
        QByteArray baRelocBlob;
        if (options.bReconstructRelocs && (result.nOEP != 0)) {
            bool bRelocatable = false;
            {
                QFile relf(sFileName);
                if (relf.open(QIODevice::ReadOnly)) {
                    XPE pe(&relf);
                    bRelocatable = pe.isValid() && pe.isRelocsPresent();
                }
            }
            if (bRelocatable) {
                const quint64 nDelta = 0x10000000ULL;
                const quint64 nBase2 = nImageBase + nDelta;
                QByteArray img1 = guCaptureImageBytes(pMM, nImageBase, nImageSize);
                QByteArray img2 = guCaptureAtBase(sFileName, emuOpt, nBase2, result.nOEP, nImageSize, options.nMaxSteps, m_pStopFlag);
                if (!img1.isEmpty() && (img1.size() == img2.size())) {
                    const QList<quint32> listRelocRvas = guDiffRelocs(img1, img2, nDelta, mainModule.bIs64);
                    baRelocBlob = guBuildRelocBlob(listRelocRvas, mainModule.bIs64);
                    emit infoMessage(tr("Reconstructed %1 base relocation(s)").arg(listRelocRvas.size()));
                } else {
                    emit infoMessage(tr("Relocation reconstruction skipped (second-base run did not reach OEP)"));
                }
            }
        }

        result.baPE = guBuildPE(pMM, nImageBase, nImageSize, result.nOEP, mainModule.bIs64, listImports, baRelocBlob, &result.nSections);
    }
    if (result.baPE.isEmpty()) {
        result.sReason = QStringLiteral("image dump failed");
        return result;
    }

    result.bSuccess = true;
    result.sReason = QStringLiteral("OEP at RVA 0x%1 (%2) after %3 steps, %4 section(s)")
                         .arg(result.nOEP, 0, 16)
                         .arg(result.sMethod)
                         .arg(nSteps)
                         .arg(result.nSections);
    return result;
}

XEmulUnpacker::RESULT XEmulUnpacker::unpackFile(const QString &sFileName, const OPTIONS &options)
{
    XEmulUnpacker unpacker;
    return unpacker.unpack(sFileName, options);
}
