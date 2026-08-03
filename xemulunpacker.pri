INCLUDEPATH += $$PWD
INCLUDEPATH += $$PWD/packers
DEPENDPATH += $$PWD
DEPENDPATH += $$PWD/packers

HEADERS += \
    $$PWD/xemulunpacker.h \
    $$PWD/xemuunpack.h \
    $$PWD/xemulunpackerfactory.h \
    $$PWD/packers/xemulunpacker_upx.h \
    $$PWD/packers/xemulunpacker_aspack.h \
    $$PWD/packers/xemulunpacker_nspack.h \
    $$PWD/packers/xemulunpacker_winupack.h \
    $$PWD/packers/xemulunpacker_fsg.h \
    $$PWD/packers/xemulunpacker_mew.h \
    $$PWD/packers/xemulunpacker_mpress.h \
    $$PWD/packers/xemulunpacker_pecompact.h \
    $$PWD/packers/xemulunpacker_acprotect.h \
    $$PWD/packers/xemulunpacker_exepack.h \
    $$PWD/packers/xemulunpacker_pex.h \
    $$PWD/packers/xemulunpacker_ahpacker.h \
    $$PWD/packers/xemulunpacker_beroexepacker.h \
    $$PWD/packers/xemulunpacker_exefog.h \
    $$PWD/packers/xemulunpacker_npack.h \
    $$PWD/packers/xemulunpacker_fishpepacker.h \
    $$PWD/packers/xemulunpacker_kkrunchy.h \
    $$PWD/packers/xemulunpacker_packman.h \
    $$PWD/packers/xemulunpacker_quickpacknt.h \
    $$PWD/packers/xemulunpacker_petite.h \
    $$PWD/packers/xemulunpacker_revprot.h

SOURCES += \
    $$PWD/xemulunpacker.cpp \
    $$PWD/xemuunpack.cpp \
    $$PWD/xemulunpackerfactory.cpp \
    $$PWD/packers/xemulunpacker_upx.cpp \
    $$PWD/packers/xemulunpacker_aspack.cpp \
    $$PWD/packers/xemulunpacker_nspack.cpp \
    $$PWD/packers/xemulunpacker_winupack.cpp \
    $$PWD/packers/xemulunpacker_fsg.cpp \
    $$PWD/packers/xemulunpacker_mew.cpp \
    $$PWD/packers/xemulunpacker_mpress.cpp \
    $$PWD/packers/xemulunpacker_pecompact.cpp \
    $$PWD/packers/xemulunpacker_acprotect.cpp \
    $$PWD/packers/xemulunpacker_exepack.cpp \
    $$PWD/packers/xemulunpacker_pex.cpp \
    $$PWD/packers/xemulunpacker_ahpacker.cpp \
    $$PWD/packers/xemulunpacker_beroexepacker.cpp \
    $$PWD/packers/xemulunpacker_exefog.cpp \
    $$PWD/packers/xemulunpacker_npack.cpp \
    $$PWD/packers/xemulunpacker_fishpepacker.cpp \
    $$PWD/packers/xemulunpacker_kkrunchy.cpp \
    $$PWD/packers/xemulunpacker_packman.cpp \
    $$PWD/packers/xemulunpacker_quickpacknt.cpp \
    $$PWD/packers/xemulunpacker_petite.cpp \
    $$PWD/packers/xemulunpacker_revprot.cpp

DISTFILES += \
    $$PWD/xemulunpacker.cmake
