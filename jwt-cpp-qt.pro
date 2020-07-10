GOOGLETEST_DIR = /usr/src

include(gtest_dependency.pri)

QT += core

TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG += thread

INCLUDEPATH += include/

HEADERS += \

SOURCES += \
    tests/TestMain.cpp \
    tests/BaseTest.cpp \
    tests/ClaimTest.cpp \
    tests/HelperTest.cpp \
    tests/TokenFormatTest.cpp \
    tests/TokenTest.cpp \
    tests/NlohmannTest.cpp

LIBS += -L/usr/lib -lssl -lcrypto
