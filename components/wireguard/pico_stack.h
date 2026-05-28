#include "Arduino.h"

// Tells the framework to isolate an independent stack for Core 1.
// This frees the shared memory space, expanding Core 0 back to a full 8KB.
extern bool core1_separate_stack;