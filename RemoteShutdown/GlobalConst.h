#pragma once

// Constants
#define DEFAULT_PORT     10102
#define PROGRAMM_GUID    "{36FCBE6F-5688-4E71-A6A8-212A090634F7}"
#define PROG_NAME        "RemoteShutdown"

#define PIPE_NAME        TEXT(R"(\\.\pipe\ProtectedPrefix\Administrators\)" PROG_NAME R"(\Pipe)");

#define RESPONSE_LIMIT   5 // seconds
#define PIPE_BUFFER_SIZE 512