.PHONY: run

run: paccap
	sudo ./paccap

paccap: main.cpp bpf_device.cpp tap_device.cpp net_util.cpp
	clang++ -std=c++11 -o $@ $^
