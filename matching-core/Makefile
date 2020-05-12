CXXFLAGS=-std=c++11 -O3 -I.

TARGET = matcher

# Parts of simbple needed for the matcher.
# Ideally this should be simplified by extracting the appropriate
# sandbox data from libsandbox.1.dylib at runtime.
CPP_OBJECTS = \
	simbple/src/dependencies/sbpldump/convert.o \
	ruleset_helpers.o

all: ${TARGET}

sandbox_utils/sandbox_utils.dylib:
	make -C sandbox_utils lib

$(CPP_OBJECTS): %.o: %.cpp
	$(CXX) $< $(CXXFLAGS) -c -o $@

${TARGET}: match_rules.cpp ${CPP_OBJECTS} sandbox_utils/sandbox_utils.dylib
	${CXX} -o $@ ${CXXFLAGS} $^

clean:
	rm -f ${TARGET} ${CPP_OBJECTS} sandbox_check
	@echo "Removed build files."
