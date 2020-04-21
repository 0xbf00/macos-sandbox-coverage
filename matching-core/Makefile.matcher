FRAMEWORKS = Foundation

CXXFLAGS=-std=c++11 -O3 -Isimbple/src -I.
CFLAGS=-O3 -Isimbple/src
LDFLAGS =-framework ${FRAMEWORKS}

TARGET = matcher

# Parts of simbple needed for the matcher.
# Ideally this should be simplified by extracting the appropriate
# sandbox data from libsandbox.1.dylib at runtime.
C_OBJECTS = \
	simbple/src/platform_data/platforms.o \
	simbple/src/sb/operations/data.o \
	simbple/src/platform_data/sierra/operations.o \
	simbple/src/platform_data/sierra/filters.o \
	simbple/src/platform_data/high_sierra/operations.o \
	simbple/src/platform_data/high_sierra/filters.o \
	simbple/src/platform_data/mojave/operations.o \
	simbple/src/platform_data/mojave/filters.o \
	simbple/src/platform_data/catalina/operations.o \
	simbple/src/platform_data/catalina/filters.o
OBJC_OBJECTS = simbple/src/misc/os_support.o
CPP_OBJECTS = \
	ruleset_helpers.o \
	sbpl_helpers.o
OBJECTS = $(C_OBJECTS) $(OBJC_OBJECTS)

all: ${TARGET}

sandbox_utils/sandbox_utils.dylib:
	make -C sandbox_utils lib

$(C_OBJECTS): %.o: %.c
$(OBJC_OBJECTS): %.o: %.m

$(CPP_OBJECTS): %.o: %.cpp
	$(CXX) $< $(CXXFLAGS) -c -o $@

${TARGET}: match_rules.cpp ${OBJECTS} ${CPP_OBJECTS} sandbox_utils/sandbox_utils.dylib
	${CXX} -o $@ ${CXXFLAGS} ${LDFLAGS} $^

$(OBJECTS):
	$(CC) $< $(CFLAGS) -c -o $@

clean:
	rm -f ${TARGET} ${OBJECTS} ${CPP_OBJECTS}
	@echo "Removed build files."
