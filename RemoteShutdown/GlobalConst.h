#pragma once

// Constants
#define INFORM_PORT      10102       // Listen-Port
#define PROGRAMM_GUID    "{36FCBE6F-5688-4E71-A6A8-212A090634F7}"
#define PROG_NAME        "RemoteShutdown"

#define SECRET_SHUTDOWN  ""
#define RESPONSE_LIMIT   5

// Preprocessor macros
#define Msg(text) MessageBox(0,text,"Meldung",MB_ICONINFORMATION | MB_SYSTEMMODAL)
#define intMsg(text,zahl) {char *tmpstring=(char*)malloc(256);char *ziffern=(char*)malloc(256);itoa(zahl,ziffern,10);strcpy(tmpstring,text);strcat(tmpstring,ziffern);Msg(tmpstring);free(tmpstring);free(ziffern);}
