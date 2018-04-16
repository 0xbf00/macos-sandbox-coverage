CXX=clang++
CXXFLAGS=-std=c++11 -O3 -I../.. -I..

MATCH_OBJ = ruleset_helpers.o sbpl_helpers.o

rematcher: ${MATCH_OBJ} rematch_inconsistent.cpp
	${CXX} -o rematcher ${CXXFLAGS} ../sandbox_utils/sandbox_utils.dylib rematch_inconsistent.cpp ${MATCH_OBJ} definition.o helpers.o

definition.o: ../../sb/operations/definition.c ../../sb/operations/definition.h
	${CXX} -o definition.o ${CXXFLAGS} -c ../../sb/operations/definition.c

helpers.o: ../../sb/operations/helpers.c ../../sb/operations/helpers.h
	${CXX} -o helpers.o ${CXXFLAGS} -c ../../sb/operations/helpers.c

ruleset_helpers.o: sbpl_helpers.o ruleset_helpers.cpp
	${CXX} -o $@ ${CXXFLAGS} -c sbpl_helpers.o ruleset_helpers.cpp

sbpl_helpers.o: definition.o helpers.o sbpl_helpers.cpp
	${CXX} -o $@ ${CXXFLAGS} -c definition.o helpers.o sbpl_helpers.cpp

all: rematcher

clean:
	rm -f rematcher ${MATCH_OBJ}
	rm -f definition.o helpers.o
	@echo "Removed build files."
