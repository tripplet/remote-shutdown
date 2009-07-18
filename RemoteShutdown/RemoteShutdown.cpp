#include "RemoteShutdown.h"


/** ########## Global variables ########## **/
bool bRunning = true;
LogFile *log;

HANDLE hNetTCPThread;
HANDLE hNetUDPThread;

/** ########## Functions ########## **/ 
bool EnableShutdownPrivNT();
bool enableDEP();
bool isUserLoggedOn();

void ServiceLoop() {
	log->writeEntry("Service started");
	hNetTCPThread = StartNetTCPLoopThread(INFORM_PORT);
	hNetUDPThread = StartNetUDPLoopThread(INFORM_PORT);
	SuspendThread(GetCurrentThread());
}

void ServiceQuit() {
	log->writeEntry("Service quit");
	TerminateThread(hNetTCPThread,0);
	TerminateThread(hNetUDPThread,0);
}

int MessageRecieved(const char* message,in_addr ip,int protocol) {
	DWORD  bufCharCount = MAX_COMPUTERNAME_LENGTH + 1;
	int compare;
	char sPCName[MAX_COMPUTERNAME_LENGTH + 1];
	char sShutdownCMD[MAX_COMPUTERNAME_LENGTH + 1 + 128];
	char sShutdownCMDAdmin[MAX_COMPUTERNAME_LENGTH + 1 + 128];
	char *sMessage = new char[strlen(message)+1];

	log->writeEntry("MessageRechived");
	
	if (protocol==UDP_MESSAGE)
		log->writeEntry("UDP:");
	else
		log->writeEntry("TCP:");
	
	log->writeEntry(message,false);

	if (0==GetComputerName(sPCName,&bufCharCount))
		return -2;

	strncpy(sMessage,message,strlen(message)+1);
	strlwr(sMessage);

	strcpy(sShutdownCMD,"shutdown ");
	strcat(sShutdownCMD,sPCName);
	strlwr(sShutdownCMD);

	strcpy(sShutdownCMDAdmin,"shutdown_admin ");
	strcat(sShutdownCMDAdmin,sPCName);
	strlwr(sShutdownCMDAdmin);

	compare = strcmpi(sMessage,sShutdownCMD);

	// normal shutdown command
	if (compare==0) {	
		delete[] sMessage;

		log->writeEntry("Shutdown command recognized");

		if (isUserLoggedOn()) {
			log->writeEntry("-> User logged on -> EXIT");
			return -1;
		}
		
		log->writeEntry("-> User not logged on");

		// get shutdown priv
		if (!EnableShutdownPrivNT()) {	
			log->writeEntry("Failed to achie ShutdownPriv -> EXIT");
			return -3;
		}

		log->writeEntry("ShutdownPriv achieved");

		// Shutdown pc
		ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG,0);
		log->writeEntry("Shutdown performed");
		return 1;
	}

	compare = strcmpi(sMessage,sShutdownCMDAdmin);

	if (compare==0) {	
		delete[] sMessage;

		log->writeEntry("Admin Shutdown command recognized");

		if (isUserLoggedOn())
			log->writeEntry("-> User logged on");
		else	
			log->writeEntry("-> User not logged on");

		// get shutdown priv
		if (!EnableShutdownPrivNT()) {	
			log->writeEntry("Failed to achie ShutdownPriv -> EXIT");
			return -3;
		}

		log->writeEntry("ShutdownPriv achieved");

		// Shutdown pc
		ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG,0);
		log->writeEntry("AdminShutdown performed");
		return 1;
	}

	return -4;
}

int main(int argc, char* argv[]) {
  if(argc>1) {
    if(strcmp(argv[1],"-i")==0) {
      if(InstallService())
        printf("\n\nService Installed Sucessfully\n");
      else
        printf("\n\nError Installing Service\n");
    }
    else if(strcmp(argv[1],"-d")==0) {
      if(DeleteService())
        printf("\n\nService UnInstalled Sucessfully\n");
      else
        printf("\n\nError UnInstalling Service\n");
    }
    else {
      printf("\n\nUnknown Switch Usage\n\nFor Install use "PROG_NAME" -i\n\nFor UnInstall use "PROG_NAME" -d\n");
    }
  }
  else {
    SERVICE_TABLE_ENTRY DispatchTable[]={{PROG_NAME,ServiceMain},{NULL,NULL}};
    StartServiceCtrlDispatcher(DispatchTable);
  }

  return 0;
}


bool isUserLoggedOn() {
  HANDLE hToken    = NULL;
  HANDLE hDupToken = NULL;

  // Get the user of the "active" session
  DWORD dwSessionId = WTSGetActiveConsoleSessionId();


  if (0xFFFFFFFF == dwSessionId) {
    // there is no active session
    return false;
  }

  BOOL ret = WTSQueryUserToken(dwSessionId, &hToken);

  if (NULL == hToken) {
    // function call failed
		return false;
  }
  
	DuplicateToken(hToken, SecurityImpersonation, &hDupToken);

  if (NULL == hDupToken) {
    CloseHandle(hToken);
    return false;
  }

  BOOL bRes = ImpersonateLoggedOnUser(hDupToken);

  if (bRes) {
    // Get the username bRes = GetUserNameA(szTempBuf, &dwBufSize); 
		// stop impersonating the user   
		RevertToSelf(); 
		return true;
  }

  CloseHandle(hDupToken);
  CloseHandle(hToken);

	return false;
}


bool EnableShutdownPrivNT() {   
  HANDLE hToken; 
  LUID DebugValue; 
  TOKEN_PRIVILEGES tkp; 

  // Retrieve a handle of the access token 
  if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&hToken))
    return false;

  // Enable the SE_DEBUG_NAME privilege 
  if (!LookupPrivilegeValue((LPSTR) NULL,SE_SHUTDOWN_NAME,&DebugValue))
    return false; 

  tkp.PrivilegeCount = 1; 
  tkp.Privileges[0].Luid = DebugValue; 
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 

  AdjustTokenPrivileges(hToken,FALSE,&tkp,sizeof(TOKEN_PRIVILEGES), 
                        (PTOKEN_PRIVILEGES) NULL,(PDWORD) NULL); 

  // The return value of AdjustTokenPrivileges can't be tested 
  if (GetLastError() != ERROR_SUCCESS)
    return false; 
 
  return true; 
}
