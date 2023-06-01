#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "string-utilities.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    utilities::string::to_upper(str);

    return 0;
}
