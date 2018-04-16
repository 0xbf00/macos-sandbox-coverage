CC=clang
CFLAGS=-O3 -fvisibility=hidden
LDFLAGS=-framework IOKit -framework CoreFoundation

SANDBOX_CHECKS = file.o posix_sem.o posix_shm.o nvram.o iokit.o signal.o process_info.o

lib: ${SANDBOX_CHECKS} sandbox_utils.c
	${CC} -dynamiclib -install_name $(shell pwd)/sandbox_utils.dylib -o sandbox_utils.dylib ${CFLAGS} sandbox_utils.c ${SANDBOX_CHECKS} ${LDFLAGS}

%.o: %.c
	${CC} -c -o $@ ${CFLAGS} $<

all: lib

clean:
	rm -f sandbox_utils.dylib ${SANDBOX_CHECKS}
	@echo "Removed build files."
