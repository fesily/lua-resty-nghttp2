OS := $(shell uname -s)
EXT = so
ifeq ($(OS), Darwin)
	EXT = dylib
endif

.PYTHON: make
make:
	cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLUA_PATH=${LUA_PATH} -DLUA_CPATH=${LUA_CPATH} -S `pwd` -B `pwd`/build.luarocks
	cd build.luarocks && make -j10

.PYTHON: install
install: 
	cd build.luarocks && cmake -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DLUA_PATH=${LUA_PATH} -DLUA_CPATH=${LUA_CPATH} -P cmake_install.cmake
	mv -f ${CMAKE_INSTALL_PREFIX}/lib/libresty_nghttp2.1.0.* ${CMAKE_INSTALL_PREFIX}/lib/libresty_nghttp2.${EXT}
	rm -f ${CMAKE_INSTALL_PREFIX}/lib/libresty_nghttp2.1*
	mv -f ${CMAKE_INSTALL_PREFIX}/lib/libnghttp2_asio.0.0.0.${EXT} ${CMAKE_INSTALL_PREFIX}/lib/libnghttp2_asio.${EXT}
	rm -f ${CMAKE_INSTALL_PREFIX}/lib/libnghttp2_asio.0*
