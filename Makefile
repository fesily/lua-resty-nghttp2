OS := $(shell uname -s)
EXT = so
LIB_NAME = ${CMAKE_INSTALL_PREFIX}/lib/libresty_nghttp2.so.1.0.0
LIB_NAME2 = ${CMAKE_INSTALL_PREFIX}/lib/libnghttp2_asio.so.0.0.0
ifeq ($(OS), Darwin)
	LIB_NAME = ${CMAKE_INSTALL_PREFIX}/lib/libresty_nghttp2.1.0.0.dylib
	LIB_NAME2 = ${CMAKE_INSTALL_PREFIX}/lib/libnghttp2_asio.0.0.0.dylib
	EXT = dylib
endif
TMP_DIR = /tmp/build_sjjjshbcxu/
PWD := $(shell pwd)

.PYTHON: make
make:
	cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLUA_PATH=${LUA_PATH} -DLUA_CPATH=${LUA_CPATH} -S ${PWD} -B ${PWD}/build.luarocks
	cd build.luarocks && make -j10

.PYTHON: install
install: 
	cd build.luarocks && cmake -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DLUA_PATH=${LUA_PATH} -DLUA_CPATH=${LUA_CPATH} -P cmake_install.cmake
ifeq ($(OS), Darwin)
	mkdir ${TMP_DIR}
	mv -f ${LIB_NAME} ${TMP_DIR}/1
	mv -f ${LIB_NAME2} ${TMP_DIR}/2
	rm -f ${CMAKE_INSTALL_PREFIX}/lib/libresty_nghttp2.*
	rm -f ${CMAKE_INSTALL_PREFIX}/lib/libnghttp2_asio.*
	mv -f ${TMP_DIR}/1 ${CMAKE_INSTALL_PREFIX}/lib/libresty_nghttp2.${EXT}
	mv -f ${TMP_DIR}/2 ${CMAKE_INSTALL_PREFIX}/lib/libnghttp2_asio.${EXT}
	rm -rf ${TMP_DIR}
endif