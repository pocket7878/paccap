#include <iostream>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <boost/format.hpp>
#include "json.hpp"
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include "device.hpp"

using namespace std;

int main(int argc, char **argv) {
  BpfDevice dev = BpfDevice("en0");
  if (dev.init() < 0) {
    return 1;
  };
  while (1) {
    std::vector<nlohmann::json> packets = dev.read_packets();
    for(auto obj : packets) {
      cout << obj.dump() << endl;
    }
  }

  cout << "Done." << endl;
  return 0;
}
