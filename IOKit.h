//#include <IOKit/IOKitLib.h>
#ifndef __IOKIT_H
#define __IOKIT_H

#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <mach/mach_types.h>
#include "IOReturn.h"

typedef mach_port_t io_connect_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_object_t;
const mach_port_t kIOMasterPortDefault;

kern_return_t
IOServiceOpen(
        io_service_t    service,
        task_port_t owningTask,
        uint32_t    type,
        io_connect_t  * connect );

kern_return_t
IOServiceClose(
        io_connect_t    connect );

CFMutableDictionaryRef
IOServiceMatching(
        const char *    name );

io_service_t
IOServiceGetMatchingService(
        mach_port_t masterPort,
        CFDictionaryRef matching );

kern_return_t
IOObjectRelease(
        io_object_t object );

kern_return_t
IOConnectCallMethod(
        mach_port_t  connection,        // In
        uint32_t     selector,      // In
        const uint64_t  *input,         // In
        uint32_t     inputCnt,      // In
        const void      *inputStruct,       // In
        size_t       inputStructCnt,    // In
        uint64_t    *output,        // Out
        uint32_t    *outputCnt,     // In/Out
        void        *outputStruct,      // Out
        size_t      *outputStructCnt);   // In/Out

kern_return_t
IOConnectCallStructMethod(
        mach_port_t  connection,        // In
        uint32_t     selector,      // In
        const void  *inputStruct,       // In
        size_t       inputStructCnt,    // In
        void        *outputStruct,      // Out
        size_t      *outputStructCnt);   // In/Out

//iokit wrappers
io_connect_t IOKit_getConnect(const char* serviceName);

IOReturn IOKit_call(const char* serviceName,
        uint32_t     selector,
        const uint64_t  *input,
        uint32_t     inputCnt,
        const void      *inputStruct,
        size_t       inputStructCnt,
        uint64_t    *output,
        uint32_t    *outputCnt,
        void        *outputStruct,
        size_t      *outputStructCnt);

#endif
