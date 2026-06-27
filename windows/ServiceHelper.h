#include <windows.h>
#include <windows.h>
#include <ntsecapi.h>
#include <winsvc.h>

#include <string>

#include "GlobalConst.h"

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD Opcode);

bool InstallCorrespondingService();
bool StartCorrespondingService();
bool DeleteCorrespondingService();

void SendMessageToService(std::string const& command);

// Implemented in Main class
void ServiceLoop(bool debugging);
void ServiceQuit();