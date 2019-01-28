.PHONY: build

build: paccap arping

paccap: paccap.cpp bpf_device.cpp tap_device.cpp net_util.cpp ethernet.cpp
	clang++ -std=c++11 -o $@ $^

arping: arping.cpp bpf_device.cpp tap_device.cpp net_util.cpp ethernet.cpp
	clang++ -std=c++11 -o $@ $^

clean:
	rm ./arping
	rm ./paccap
