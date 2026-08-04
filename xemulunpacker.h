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
#ifndef XEMULUNPACKER_H
#define XEMULUNPACKER_H

#include <QByteArray>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>

#include "xbinary.h"
#include "xemuemulator.h"

// Generic, packer-agnostic emulation unpacker.
//
// It loads a packed executable into XEmuEmulator, single-steps the loader stub
// while watching for the transfer to the original entry point (OEP), then dumps
// the reconstructed in-memory image as a PE.
//
// OEP detection is based on the classic *write-then-execute* tell: a packer
// decompresses code into memory and then jumps into it. Every guest write is
// tracked at page granularity; when execution reaches an address inside the main
// image, on a page that was written during this run, and outside the stub's own
// entry section, that address is taken as the OEP. Plain *section-hop* (execution
// leaving the entry section into another part of the image) is kept as a fallback
// for stubs whose OEP page our write tracking did not cover.
//
// The class is stateful and reports progress/diagnostics through the caller's
// XBinary::PDSTRUCT (status lines via the info string + callback; cancellation via
// isPdStructStopped), so a GUI front end can drive it, stream what the stub is doing
// and stop it. It is packer-agnostic: it works for any stub the CPU core can execute
// up to the OEP transfer (UPX, ASPack, FSG, MEW, Petite, ...).
class XEmulUnpacker : public QObject {
    Q_OBJECT

public:
    explicit XEmulUnpacker(QObject *pParent = nullptr);
    ~XEmulUnpacker() override;

    struct OPTIONS {
        qint64 nMaxSteps;          // instruction budget before giving up
        bool bLoadDependencies;    // map real dependency DLLs (needs sSystemRoot)
        QString sSystemRoot;       // directory searched for dependency modules
        bool bDetectWriteExec;     // enable OEP detection (cross-section transfer into written memory)
        bool bDetectSectionHop;    // last-resort fallback: accept a cross-section transfer into raw memory too
        qint64 nProgressInterval;  // reserved (progress heartbeat interval; currently unused)
        bool bCaptureApiLog;       // record emulated Windows-API calls in the result
        int nMaxApiLog;            // cap on captured API-log lines

        // OEP-candidate gating. A multi-stage packer can jump into freshly written memory
        // (its own next decompressor stage) very early, long before the real hand-off. A
        // genuine OEP transfer only happens after the stub has actually decompressed the
        // image, i.e. run a non-trivial number of instructions; candidates seen before
        // nOepMinStubSteps are premature stage jumps and are ignored.
        qint64 nOepMinStubSteps;  // minimum stub instructions before a cross-section transfer can be the OEP

        // Deferred write-then-execute (multi-stage loaders). Some packers (older MPRESS)
        // jump into a *second loader stage* in written memory before the real hand-off; the
        // plain write-then-execute heuristic would stop there. When > 0, the first
        // write-then-execute candidate is remembered but NOT taken immediately: the run
        // continues so a packer-signature matchOEP() (e.g. MPRESS's "add esp,0x28; pop-seq;
        // jmp OEP" tail) can fire and win. If no signature fires within this many steps of
        // the remembered candidate (a single-stage stub whose first write-exec jump already
        // is the OEP), the remembered candidate is taken. 0 = take the first candidate at once.
        qint64 nOepDeferTailSteps;

        // Reconstruct the import table (rebuild IMAGE_IMPORT_DESCRIPTORs + INT/name tables and
        // DataDirectory[1]) so the dumped image is runnable. On by default; turn off to get a
        // raw dump whose IAT still points at the emulator's stub arena (diagnostics only).
        bool bReconstructImports;

        // Reconstruct base relocations for a relocatable image (mostly DLLs): run the stub a
        // SECOND time at a different image base and diff the two unpacked images -- any location
        // that moved by exactly the base delta is an absolute address that needs a relocation.
        // Rebuilds a real .reloc + DataDirectory[5] so the output can load at any base instead
        // of only its preferred one. Doubles the unpack time; skipped for non-relocatable
        // images (which stay RELOCS_STRIPPED, correct for a preferred-base-only dump).
        bool bReconstructRelocs;

        OPTIONS()
            : nMaxSteps(100000000), bLoadDependencies(false), bDetectWriteExec(true), bDetectSectionHop(false), nProgressInterval(1000000),
              bCaptureApiLog(true), nMaxApiLog(4096), nOepMinStubSteps(5000), nOepDeferTailSteps(0), bReconstructImports(true),
              bReconstructRelocs(true)
        {
        }
    };

    struct RESULT {
        bool bSuccess;
        quint64 nOEP;           // recovered original entry point (RVA)
        quint64 nImageBase;
        quint64 nImageSize;
        qint64 nSteps;          // instructions executed
        int nSections;          // sections written into the rebuilt image
        int nImports;           // imports recovered into the reconstructed import table
        QByteArray baPE;        // rebuilt PE (valid only when bSuccess)
        QString sMethod;        // which heuristic fired ("write-then-execute" / "section-hop")
        QString sReason;        // human-readable stop reason / diagnostics
        QStringList listApiLog;  // emulated Windows-API calls the stub made

        RESULT() : bSuccess(false), nOEP(0), nImageBase(0), nImageSize(0), nSteps(0), nSections(0), nImports(0)
        {
        }
    };

    // Description of a single control-flow transfer the stub makes, handed to
    // matchOEP() so a packer subclass can recognise its stub's characteristic
    // hand-off to the original entry point. It carries the classic per-packer
    // "tells": the terminating instruction (opcode bytes + length), whether the
    // stack is balanced back to its initial value, and the direction of the jump
    // between memory pages. (Ported from the per-packer OEP heuristics in the
    // legacy QEmulX engine, whose "section" comparison was a page comparison.)
    struct OEP_CONTEXT {
        quint64 nPrevAddress;    // address of the terminating instruction ("prev")
        quint32 nPrevSize;       // its length in bytes
        QByteArray baPrevCode;   // its opcode bytes (up to 16)
        quint64 nCurrAddress;    // transfer target -- the OEP candidate ("curr")
        qint64 nSpDelta;         // stack pointer minus initial stack pointer (0 == fully balanced)
        bool bJumpFromHigh;      // prev page > curr page (jump down to a lower section)
        bool bJumpToHigh;        // prev page < curr page
        bool bJumpFromHeader;    // prev page == image base (executing from the PE header page)
        bool bPrevIsImage;       // terminating instruction lies inside the main image
        bool bCurrIsImage;       // target lies inside the main image
        bool bPrevIsHeap;        // terminating instruction lies in an allocated (non-image, non-stack) region
        bool bDirtyTarget;       // target page was written during this run
        qint64 nSteps;           // instructions executed so far
        quint64 nImageBase;
        quint64 nImageSize;
        XEmuMemoryManager *pMemoryManager;  // for predicates that inspect bytes around prev

        OEP_CONTEXT()
            : nPrevAddress(0), nPrevSize(0), nCurrAddress(0), nSpDelta(0), bJumpFromHigh(false), bJumpToHigh(false), bJumpFromHeader(false),
              bPrevIsImage(false), bCurrIsImage(false), bPrevIsHeap(false), bDirtyTarget(false), nSteps(0), nImageBase(0), nImageSize(0),
              pMemoryManager(nullptr)
        {
        }

        // Little-endian view of the first bytes of the terminating instruction.
        quint8 prev8() const;
        quint16 prev16() const;
        quint32 prev32() const;

        // Match a wildcard hex pattern against guest memory at nAddress. '.' matches
        // any nibble (e.g. "669D83c4.." matches popa/popf/add esp,<any imm8>). Returns
        // false if the bytes cannot be read.
        bool matchSignature(quint64 nAddress, const char *pszHexPattern) const;
    };

    // Packer-family id this unpacker specialises in. The generic base returns
    // "generic"; each packer subclass (XEmulUnpackerUPX, XEmulUnpackerASPack, ...)
    // returns its packer name.
    virtual QString getPackerName() const;

    // Packer-tuned default options. The generic base returns a plain OPTIONS();
    // every packer subclass overrides this with values tuned for that stub family
    // (instruction budget, OEP-candidate gating, section-hop fallback, ...). The
    // single-argument unpack() overload runs with these.
    virtual OPTIONS getDefaultOptions() const;

    // Progress + diagnostics flow through pPdStruct: status lines via the info string
    // (streamed through the PDSTRUCT callback), cancellation via isPdStructStopped() --
    // the stepping loop polls it and stops promptly (reason "cancelled") when set. The
    // PDSTRUCT is owned by the caller (e.g. a GUI worker thread), so another thread can
    // request a stop while unpack() runs. Pass a valid PDSTRUCT (createPdStruct()).
    RESULT unpack(const QString &sFileName, const OPTIONS &options, XBinary::PDSTRUCT *pPdStruct);
    // Unpack using this unpacker's getDefaultOptions() (packer-tuned in subclasses), with a
    // throwaway PDSTRUCT (no progress/cancellation).
    RESULT unpack(const QString &sFileName);

    // Convenience one-shot for callers that do not need progress/cancellation.
    static RESULT unpackFile(const QString &sFileName, const OPTIONS &options = OPTIONS());

protected:
    // Decide whether the control transfer described by ctx is the stub's hand-off to
    // the original entry point. The generic base returns false (it relies solely on
    // the write-then-execute / section-hop heuristic in unpack()); each packer
    // subclass overrides this with the exact terminating-instruction signature of
    // its stub family. When it fires, its return address is taken as the OEP; when it
    // never fires, unpack() still falls back to the generic heuristic.
    virtual bool matchOEP(const OEP_CONTEXT &ctx, const OPTIONS &options) const;

    // Last-resort OEP recovery when the run STOPPED (halt/fault) with no OEP found: a packer
    // subclass may scan the (dumped) entry section for a stored absolute OEP its stub would have
    // jumped to. Returns an absolute VA (0 = give up). The base returns 0 -> no effect for any
    // family without an override. The caller validates the result (in-image, cross-section, dirty).
    virtual quint64 recoverOepAtStop(XEmuMemoryManager *pMemoryManager, quint64 nScanStart, quint64 nScanEnd,
                                     quint64 nImageBase, quint64 nImageSize) const;

private:
    // Caller-owned progress/cancellation struct for the current unpack() run (set at its
    // start; nullptr outside a run). Status is reported through it and the stepping loop
    // polls it for cancellation.
    XBinary::PDSTRUCT *m_pPdStruct = nullptr;

    // Report a diagnostic line: set it as the PDSTRUCT info string and fire the callback
    // (unthrottled) so a front end can stream it live. No-op without a PDSTRUCT.
    void reportInfo(const QString &sText);


    // Rebuild the original ELF from the decompressed image the stub laid out in
    // memory (used when the target is a dynamically-linked ELF that cannot be run to
    // its entry point without a real ld.so on disk). Reads the decompressed ELF
    // header + program headers from nImageBase and reassembles the file. Returns
    // empty if no valid decompressed ELF is present.
    static QByteArray _reconstructElfFromMemory(XEmuMemoryManager *pMemoryManager, quint64 nImageBase, quint64 *pnEntry, int *pnSegments);

    // Wrap the decompressed in-memory image as a minimal Mach-O (one LC_SEGMENT per
    // committed region + an LC_UNIXTHREAD carrying the recovered entry point).
    static QByteArray _buildMachO(XEmuMemoryManager *pMemoryManager, quint64 nImageBase, quint64 nImageSize, quint64 nOepAbs, bool bIs64,
                                  quint32 nCpuType, quint32 nCpuSubtype, int *pnSegments);
};

#endif  // XEMULUNPACKER_H
