About
=====

OllyHeapTrace (Written in 2008) is a plugin for OllyDbg (version 1.10) to trace the heap operations being performed by a process. It will monitor heap allocations and frees for multiple heaps, as well as operations such as creating or destroying heaps and reallocations. All parameters as well as return values are recorded and the trace is highlighted with a unique colour for each heap being traced.

The primary purpose of this plugin is to aid in the debugging of heap overflows where you wish to be able to control the heap layout to overwrite a specific structure such as a chunk header, critical section structure or some application specific data. By tracing the heap operations performed during actions you can control (for example opening a connection, sending a packet, closing a connection) you can begin to predict the heap operations and thus control the heap layout. 

Build
=====

To build OllyHeapTrace from source, checkout the latest revision from the SVN trunk and then open OllyHeapTraceGroup.bdsgroup with either Borland's Turbo C++ Explorer (free) or any recent version of C++ Builder and build the OllyHeapTrace project. 

Usage
=====

Simply install the plugin and activate OllyHeapTrace when you wish to begin tracing heap operations. OllyHeapTrace will automatically create the breakpoints needed (RtlAllocateHeap, RtlFreeHeap, RtlCreateHeap, RtlDestroyHeap, RtlReAllocateHeap, RtlSizeHeap, GetProcessHeap and RtlInitializeCriticalSection, RtlDeleteCriticalSection) and record the relevant information when these breakpoints are hit. To view the heap trace select the OllyHeapTrace Log.

Double clicking on any row in the OllyHeapTrace Log window will bring you to the callers location in the OllyDbg disassembly window. The recorded heap trace is highlighted with a unique colour for each heap being traced. Right clicking on any row will give you some options such as to view the heap chunks data or the heap itself (only a raw dump of the memory is given, no parsing of the heap structures is performed). You can also filter out unwanted information if you are only concerned with a specific heap. 

Screenshot
==========

![OllyHeapTrace Screenshot 1](https://github.com/stephenfewer/OllyHeapTrace/raw/master/screenshot1.gif "OllyHeapTrace Screenshot 1")

License
=======

The OllyHeapTrace source code is available under the GPLv3 license, please see the included file gpl-3.0.txt for details.
