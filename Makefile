GPP = g++
DEST = out/openssl
OPENSSLDEST = $(abspath $(lastword $(DEST)))
# .DEFAULT_GOAL := croxy

croxy: openssl openssl_sw_install
	$(GPP) -std=c++11 $< -o $@ -I./out/llhttp -L./out/llhttp -lllhttp -I./out/openssl/include -L./out/openssl/lib64 -lssl -lcrypto

clean:
	rm -rf croxy && rm -rf out/*

llhttp:
	cd deps/llhttp && npm install && cd ../.. && cp -r deps/llhttp/build out/llhttp

openssl:
	mkdir -p out/openssl
	cd deps/openssl && ./Configure --prefix=$(OPENSSLDEST)

openssl_sw_install: openssl
	cd deps/openssl && make -j10 build_sw && make -j10 install_sw

echo_job:
	echo $(JOBS)

.PHONY: clean
