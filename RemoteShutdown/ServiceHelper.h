#include <windows.h>
#include <windows.h>
#include <ntsecapi.h>
#include <winsvc.h>

#include "GlobalConst.h"
#include "LogFile.h"

/** ########## Functions ########## **/ 
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD Opcode);
bool enableDEP();
BOOL InstallService();
BOOL DeleteService();

// Implement in Mmin class
void ServiceLoop();
void ServiceQuit();