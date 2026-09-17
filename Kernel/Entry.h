#pragma once

#include <ntifs.h>

/*++

Module Name:

    Entry.h

Abstract:

    This module declares the driver's load and unload entry points.

--*/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

DRIVER_UNLOAD DriverUnload;

EXTERN_C_END
