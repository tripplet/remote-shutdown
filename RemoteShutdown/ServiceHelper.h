#include <windows.h>
#include <windows.h>
#include <ntsecapi.h>
#include <winsvc.h>

#include "GlobalConst.h"

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD Opcode);

bool InstallCorrespondingService();
bool StartCorrespondingService();
bool DeleteCorrespondingService();

// Implement in Mmin class
void ServiceLoop();
void ServiceQuit();