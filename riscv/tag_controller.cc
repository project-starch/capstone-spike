#include "tag_controller.h"

// return true if the CLEN-bit memory location is tagged as a capability
bool
TagController::getTag(uint64_t addr) const {
  addr &= ~(uint64_t(CLENBYTES - 1));
  auto it = taggedAddresses.find(addr);
  return it != taggedAddresses.end();
}

// set the CLEN-bit memory location as a capability or as an integer
void
TagController::setTag(uint64_t addr, bool as_cap) {
  addr &= ~(uint64_t(CLENBYTES - 1));
  if(as_cap) {
    taggedAddresses.insert(addr);
  } else{
    taggedAddresses.erase(addr);
  }
}
