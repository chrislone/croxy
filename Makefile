GPP = g++
# .DEFAULT_GOAL := croxy

croxy: main.cc
	$(GPP) -static -std=c++11 $< -o $@ -I./deps -L./deps/llhttp -lllhttp -I./deps/openssl/include -L./deps/openssl/lib64 -lssl -lcrypto

clean:
	rm -rf croxy

.PHONY: clean
