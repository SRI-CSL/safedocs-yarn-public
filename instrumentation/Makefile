# SPDX-License-Identifier: MIT
build/libmemcalltrace.so: build *.c *.h mem-trace.c build/Makefile
	cd build; make
	@if [ -d /build ]; then cp -r build/* /build; fi;

build/Makefile: build CMakeLists.txt
	cd build;  cmake -DCMAKE_BUILD_TYPE=Debug ..

build:
	mkdir build

cleanresults:
	-rm build/*.log
	-rm -rf test/_test

clean:
	rm -rf build

.PHONY: clean cleanresults
