#ifndef __CAPSTONE_TAG_CONTROLLER_H__
#define __CAPSTONE_TAG_CONTROLLER_H__

#include "cap.h"
#include <unordered_set>

const uint64_t WORD_SIZE = 16;

class TagController
{
private:
    std::unordered_set<uint64_t> taggedAddresses;

public:
    void setTag(uint64_t addr, bool as_cap);
    bool getTag(uint64_t addr) const;
};

#endif
