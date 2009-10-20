#include "ServiceHelper.h"

SERVICE_STATUS m_ServiceStatus;
SERVICE_STATUS_HANDLE m_ServiceStatusHandle;

extern bool bRunning;
extern LogFile *log;

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
  PSECURITY_LOGON_SESSION_DATA sessionData = NULL;

	enableDEP();

	log = new LogFile("C:\\RemoteLog.txt");

  m_ServiceStatus.dwServiceType = SERVICE_WIN32;
  m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
  m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  m_ServiceStatus.dwWin32ExitCode = 0;
  m_ServiceStatus.dwServiceSpecificExitCode = 0;
  m_ServiceStatus.dwCheckPoint = 0;
  m_ServiceStatus.dwWaitHint = 0;

  m_ServiceStatusHandle = RegisterServiceCtrlHandler(PROG_NAME,ServiceCtrlHandler); 
 
	if (m_ServiceStatusHandle == (SERVICE_STATUS_HANDLE)0) {
    return;
  }

  m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
  m_ServiceStatus.dwCheckPoint = 0;
  m_ServiceStatus.dwWaitHint = 0;
  
	if (!SetServiceStatus (m_ServiceStatusHandle, &m_ServiceStatus)) {
  }

  bRunning=true;

  while(bRunning) {
		ServiceLoop();
  }

	ServiceQuit();	
	delete log;

  return;
}

void WINAPI ServiceCtrlHandler(DWORD Opcode) {
  switch(Opcode) {
    case SERVICE_CONTROL_PAUSE: 
      m_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
      break;
    case SERVICE_CONTROL_CONTINUE:
      m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
      break;
    case SERVICE_CONTROL_STOP:
      m_ServiceStatus.dwWin32ExitCode = 0;
      m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
      m_ServiceStatus.dwCheckPoint = 0;
      m_ServiceStatus.dwWaitHint = 0;

      SetServiceStatus (m_ServiceStatusHandle,&m_ServiceStatus);
      bRunning=false;
      break;
    case SERVICE_CONTROL_INTERROGATE:
      break; 
  }
  return;
}

char *AppPath() {
  char *sFilePath = new char[1024];

  HMODULE hModule = GetModuleHandle(0);	 
  GetModuleFileName(hModule,sFilePath,1024);
  return sFilePath;
}

bool enableDEP() {
	typedef BOOL (WINAPI *DLLPROC)(DWORD);
	DLLPROC ProcAddr; 
	HMODULE hDLL;

	hDLL = LoadLibrary("kernel32.dll");
	if (hDLL != NULL) {
		ProcAddr = (DLLPROC)GetProcAddress(hDLL,"SetProcessDEPPolicy");

		if (!ProcAddr) {
			FreeLibrary(hDLL);
			return false;
		 }
		 else {
			// try enable DEP => SetProcessDEPPolicy(PROCESS_DEP_ENABLE)
			return (ProcAddr(1) == TRUE);
		}
	}
	
	return false;
}

BOOL InstallService() {
  SC_HANDLE schSCManager,schService;
  char *strPath = AppPath();

	schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);

	if (schSCManager == NULL) {
		delete[] strPath;
    return false;
	}

  schService = CreateService(schSCManager,PROG_NAME, 
	   PROG_NAME, // service name to display

     SERVICE_ALL_ACCESS, // desired access 

     SERVICE_WIN32_OWN_PROCESS, // service type 

		 SERVICE_AUTO_START, // start type 

     SERVICE_ERROR_NORMAL, // error control type 

     (LPCTSTR)strPath, // service's binary 

     NULL, // no load ordering group 

     NULL, // no tag identifier 

     NULL, // no dependencies

     NULL, // LocalSystem account

     NULL); // no password

	SERVICE_DESCRIPTION sd;
	sd.lpDescription = "Ermöglicht das Herunterfahren des PCs per Netzwerk";

	ChangeServiceConfig2(schService,SERVICE_CONFIG_DESCRIPTION,&sd);

	delete[] strPath;

  if (schService == NULL)
    return false; 

  CloseServiceHandle(schService);
  return true;	
}

BOOL DeleteService() {
  SC_HANDLE schSCManager;
  SC_HANDLE hService;
  schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);

  if (schSCManager == NULL)
    return false;
  hService=OpenService(schSCManager,PROG_NAME,SERVICE_ALL_ACCESS);
  if (hService == NULL)
    return false;
  if(DeleteService(hService)==0)
    return false;
  if(CloseServiceHandle(hService)==0)
    return false;

	return true;
}