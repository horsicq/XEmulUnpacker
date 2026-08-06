# XEmulUnpacker - generic, packer-agnostic emulation unpacker built on XEmulator.
#
# Loads a packed executable into the XEmulator CPU core, single-steps the loader
# stub while watching for the transfer to the original entry point (OEP), then
# dumps the reconstructed in-memory image as a PE (ELF / Mach-O fallbacks too).
#
# The packers/ subfolder holds one XEmulUnpacker subclass per known packer/protector
# family (UPX, ASPack, FSG, ...), each overriding matchOEP() with the terminating-
# instruction signature of its stub (ported from the legacy QEmulX engine).
#
# Usage (as a _mylibs source-list library):
#   include(${CMAKE_CURRENT_LIST_DIR}/../../_mylibs/XEmulUnpacker/xemulunpacker.cmake)
#   add_executable(MyApp ${XEMULUNPACKER_SOURCES} main.cpp ...)
#
# Pulls in the full XEmulator core (xemulator.cmake) it is built on top of, so
# consumers only need to include this file.

if(NOT DEFINED XEMULUNPACKER_SOURCES)

include(${CMAKE_CURRENT_LIST_DIR}/../XEmulator/xemulator.cmake)

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/packers)

set(XEMULUNPACKER_SOURCES
    ${XEMULATOR_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xemulunpacker.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xemulunpacker.h
    ${CMAKE_CURRENT_LIST_DIR}/xemuunpack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xemuunpack.h
    ${CMAKE_CURRENT_LIST_DIR}/xemulunpackerfactory.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xemulunpackerfactory.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_upx.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_upx.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_aspack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_aspack.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_armadillo.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_armadillo.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_nspack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_nspack.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_winupack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_winupack.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_fatpack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_fatpack.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_fsg.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_fsg.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_mew.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_mew.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_mpress.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_mpress.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pecompact.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pecompact.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_acprotect.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_acprotect.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_exepack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_exepack.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pex.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pex.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_ahpacker.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_ahpacker.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_beroexepacker.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_beroexepacker.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_exefog.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_exefog.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_npack.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_npack.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_fishpepacker.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_fishpepacker.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_kkrunchy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_kkrunchy.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_packman.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_packman.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_quickpacknt.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_quickpacknt.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_packedinfectedpe.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_packedinfectedpe.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pefilepacker.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pefilepacker.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pespin.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pespin.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_petite.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_petite.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pepacker_levanvn.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_pepacker_levanvn.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_revprot.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_revprot.h
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_themida.cpp
    ${CMAKE_CURRENT_LIST_DIR}/packers/xemulunpacker_themida.h
)

endif()