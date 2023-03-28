#include "tag_controller.h"

// Unaligned cases are handled by MMU before calling this function.
// Return value: tag_is_cap
bool
TagController::getTag(uint64_t addr) const {
  addr &= ~(WORD_SIZE - 1);
  auto it = taggedAddresses.find(addr);
  return it != taggedAddresses.end();
}

void
TagController::setTag(uint64_t addr, bool as_cap) {
  addr &= ~(WORD_SIZE - 1);
  if(as_cap) {
    taggedAddresses.insert(addr);
  } else{
    taggedAddresses.erase(addr);
  }
}
