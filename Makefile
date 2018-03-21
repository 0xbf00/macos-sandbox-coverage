CXX=clang++
CXXFLAGS=-std=c++11 -O3 -I..

SBPL_OBJ = definition.o helpers.o

matcher: ${SBPL_OBJ} match_rules.cpp
	${CXX} -o matcher ${CXXFLAGS} match_rules.cpp ${SBPL_OBJ}

definition.o: ../sb/operations/definition.c ../sb/operations/definition.h
	${CXX} -o definition.o ${CXXFLAGS} -c ../sb/operations/definition.c

helpers.o: ../sb/operations/helpers.c ../sb/operations/helpers.h
	${CXX} -o helpers.o ${CXXFLAGS} -c ../sb/operations/helpers.c


all: matcher

clean:
	rm -f matcher ${SBPL_OBJ}
	@echo "Removed build files."
