// Include stdbool.h to introduce `bool`
#include "stdbool.h"

// Include defines.h and then redefine the SEAL_C_FUNC macro to remove the `extern "C"`
#include "seal/c/defines.h"
#define SEAL_C_FUNC HRESULT
