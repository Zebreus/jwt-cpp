isEmpty(GOOGLETEST_DIR):GOOGLETEST_DIR=$$(GOOGLETEST_DIR)

isEmpty(GOOGLETEST_DIR) {
    GOOGLETEST_DIR = 
    !isEmpty(GOOGLETEST_DIR) {
        warning("Using googletest src dir specified at Qt Creator wizard")
        message("set GOOGLETEST_DIR as environment variable or qmake variable to get rid of this message")
    }
}

!isEmpty(GOOGLETEST_DIR): {
    GTEST_SRCDIR = $$GOOGLETEST_DIR/googletest
} else: unix {
    exists(/usr/src/gtest):GTEST_SRCDIR=/usr/src/gtest
    !isEmpty(GTEST_SRCDIR): message("Using gtest from system")
}

requires(exists($$GTEST_SRCDIR))

DEFINES += \
    GTEST_LANG_CXX11

!isEmpty(GTEST_SRCDIR) {
    INCLUDEPATH *= \
        $$GTEST_SRCDIR \
        $$GTEST_SRCDIR/include

    SOURCES += \
        $$GTEST_SRCDIR/src/gtest-all.cc
}
