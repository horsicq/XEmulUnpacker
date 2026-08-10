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
#include "xemulunpackerfactory.h"

#include "packers/xemulunpacker_acprotect.h"
#include "packers/xemulunpacker_ahpacker.h"
#include "packers/xemulunpacker_alushpacker.h"
#include "packers/xemulunpacker_armadillo.h"
#include "packers/xemulunpacker_aspack.h"
#include "packers/xemulunpacker_beroexepacker.h"
#include "packers/xemulunpacker_eronana.h"
#include "packers/xemulunpacker_exefog.h"
#include "packers/xemulunpacker_exepack.h"
#include "packers/xemulunpacker_fatpack.h"
#include "packers/xemulunpacker_fishpepacker.h"
#include "packers/xemulunpacker_fsg.h"
#include "packers/xemulunpacker_kkrunchy.h"
#include "packers/xemulunpacker_mew.h"
#include "packers/xemulunpacker_mpress.h"
#include "packers/xemulunpacker_neolite.h"
#include "packers/xemulunpacker_npack.h"
#include "packers/xemulunpacker_nspack.h"
#include "packers/xemulunpacker_packedinfectedpe.h"
#include "packers/xemulunpacker_packman.h"
#include "packers/xemulunpacker_pecompact.h"
#include "packers/xemulunpacker_pefilepacker.h"
#include "packers/xemulunpacker_pepacker_levanvn.h"
#include "packers/xemulunpacker_pespin.h"
#include "packers/xemulunpacker_petite.h"
#include "packers/xemulunpacker_pex.h"
#include "packers/xemulunpacker_pinkiepie.h"
#include "packers/xemulunpacker_quickpacknt.h"
#include "packers/xemulunpacker_revprot.h"
#include "packers/xemulunpacker_themida.h"
#include "packers/xemulunpacker_tinyload.h"
#include "packers/xemulunpacker_uchiha.h"
#include "packers/xemulunpacker_upx.h"
#include "packers/xemulunpacker_winupack.h"
#include "packers/xemulunpacker_xorpacker.h"

namespace {

template <typename T>
XEmulUnpacker *make(QObject *pParent)
{
    return new T(pParent);
}

struct ENTRY {
    const char *pszName;                        // matches the subclass getPackerName()
    XEmulUnpacker *(*pfnCreate)(QObject *pParent);
};

// Kept in the same order the corpus / QEmulX enum lists them.
const ENTRY g_entries[] = {
    {"Uchiha", &make<XEmulUnpackerUchiha>},
    {"UPX", &make<XEmulUnpackerUPX>},
    {"ASPack", &make<XEmulUnpackerASPack>},
    {"Armadillo", &make<XEmulUnpackerArmadillo>},
    {"NSPack", &make<XEmulUnpackerNSPack>},
    {"(Win)Upack", &make<XEmulUnpackerWinupack>},
    {"Fatpack (x64 LZMA Manual Mapper)", &make<XEmulUnpackerFatpack>},
    {"FSG", &make<XEmulUnpackerFSG>},
    {"MEW", &make<XEmulUnpackerMEW>},
    {"MPRESS", &make<XEmulUnpackerMPRESS>},
    {"PECompact", &make<XEmulUnpackerPECompact>},
    {"ACProtect", &make<XEmulUnpackerACProtect>},
    {"!EP(EXE Pack)", &make<XEmulUnpackerEXEPack>},
    {"PeX", &make<XEmulUnpackerPeX>},
    {"pinkie-pie", &make<XEmulUnpackerPinkiePie>},
    {"AHPacker", &make<XEmulUnpackerAHPacker>},
    {"AlushPacker", &make<XEmulUnpackerAlushPacker>},
    {"BeRoEXEPacker", &make<XEmulUnpackerBeRoEXEPacker>},
    {"Eronana Packer", &make<XEmulUnpackerEronana>},
    {"ExeFog", &make<XEmulUnpackerExeFog>},
    {"NeoLite", &make<XEmulUnpackerNeoLite>},
    {"nPack", &make<XEmulUnpackerNPack>},
    {"Fish PE Packer", &make<XEmulUnpackerFishPEPacker>},
    {"kkrunchy", &make<XEmulUnpackerKKrunchy>},
    {"Packman", &make<XEmulUnpackerPackman>},
    {"QuickPack NT", &make<XEmulUnpackerQuickPackNT>},
    {"Packed-Infected-PE", &make<XEmulUnpackerPackedInfectedPE>},
    {"PE-File-Packer (Chronoss3)", &make<XEmulUnpackerPEFilePacker>},
    {"PESpin", &make<XEmulUnpackerPESpin>},
    {"Petite", &make<XEmulUnpackerPetite>},
    {"PE Packer by levanvn", &make<XEmulUnpackerPEPackerLevanvn>},
    {"REVProt", &make<XEmulUnpackerRevProt>},
    {"Themida", &make<XEmulUnpackerThemida>},
    {"TinyLoad", &make<XEmulUnpackerTinyLoad>},
    {"xor-packer", &make<XEmulUnpackerXorPacker>},
};

}  // namespace

QString XEmulUnpackerFactory::genericName()
{
    return QStringLiteral("Generic (auto)");
}

QStringList XEmulUnpackerFactory::packerNames()
{
    QStringList listResult;
    listResult.append(genericName());
    for (const ENTRY &entry : g_entries) {
        listResult.append(QString::fromUtf8(entry.pszName));
    }
    return listResult;
}

XEmulUnpacker *XEmulUnpackerFactory::create(const QString &sPackerName, QObject *pParent)
{
    for (const ENTRY &entry : g_entries) {
        if (sPackerName == QLatin1String(entry.pszName)) {
            return entry.pfnCreate(pParent);
        }
    }
    // genericName(), empty, or any unknown packer -> the base heuristic unpacker.
    return new XEmulUnpacker(pParent);
}
