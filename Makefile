PWD := $(shell pwd)

.PYTHON: make
make:
	cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLUA_PATH=${LUA_PATH} -DLUA_CPATH=${LUA_CPATH} -S ${PWD} -B ${PWD}/build.luarocks
	cd build.luarocks && make -j10

.PYTHON: install
install: 
	cd build.luarocks && \
	cmake -P ${PWD}/build.luarocks/_deps/nghttp2-asio-build/cmake_install.cmake &&\
 	cmake -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DLUA_PATH=${LUA_PATH} -DLUA_CPATH=${LUA_CPATH} -DCMAKE_INSTALL_LOCAL_ONLY=ON -P cmake_install.cmake