#include "RemoteShutdown.h"


/** ########## Global variables ########## **/
bool bRunning = true;
LogFile *loggingFile;

HANDLE hNetTCPThread;
HANDLE hNetUDPThread;

/** ########## Functions ########## **/ 
bool EnableShutdownPrivNT();
bool enableDEP();
bool isUserLoggedOn();
bool isRemoteUserLoggedIn();

void ServiceLoop() {
	loggingFile->writeEntry("Service started");
	hNetTCPThread = StartNetTCPLoopThread(INFORM_PORT);
	hNetUDPThread = StartNetUDPLoopThread(INFORM_PORT);
	SuspendThread(GetCurrentThread());
}

void ServiceQuit() {
	loggingFile->writeEntry("Service quit");
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

	if (strlen(message)==0)
		return -10;

  loggingFile->newTmpEntry();
	loggingFile->addTmpEntry("MessageRechived ");
	
	if (protocol==UDP_MESSAGE)
		loggingFile->addTmpEntry("(UDP): ");
	else
		loggingFile->addTmpEntry("(TCP): ");
	
	loggingFile->addTmpEntry(message);
  loggingFile->writeTmpEntry();

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

    loggingFile->newTmpEntry();
		loggingFile->addTmpEntry("Shutdown command recognized");

		if (isUserLoggedOn()) {
			loggingFile->addTmpEntry(" -> User logged in -> ABORT\n");
      loggingFile->writeTmpEntry();
			return -1;
		}

		if (isRemoteUserLoggedIn()) {
			loggingFile->addTmpEntry(" -> RemoteUser logged in -> ABORT\n");
      loggingFile->writeTmpEntry();
			return -1;
		}		
		
		loggingFile->writeEntry(" -> User not logged in");

		// get shutdown priv
		if (!EnableShutdownPrivNT()) {	
			loggingFile->addTmpEntry(" -> Failed to achieve ShutdownPriv -> ABORT\n");
      loggingFile->writeTmpEntry();
			return -3;
		}

		loggingFile->addTmpEntry(" -> ShutdownPriv achieved");

		// Shutdown pc
		ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG,0);
		loggingFile->addTmpEntry(" -> Shutdown performed");
    loggingFile->writeTmpEntry();
		return 1;
	}

	compare = strcmpi(sMessage,sShutdownCMDAdmin);

	if (compare==0) {	
		delete[] sMessage;

    loggingFile->newTmpEntry();
		loggingFile->addTmpEntry("Admin Shutdown command recognized");

		if (isUserLoggedOn())
			loggingFile->addTmpEntry(" -> User logged in");
		else if (isRemoteUserLoggedIn())
			loggingFile->addTmpEntry(" -> RemoteUser logged in");
		else
			loggingFile->addTmpEntry(" -> User not logged on");

		// get shutdown priv
		if (!EnableShutdownPrivNT()) {	
			loggingFile->addTmpEntry(" -> Failed to achieve ShutdownPriv -> ABORT\n");
      loggingFile->writeTmpEntry();
			return -3;
		}

		loggingFile->addTmpEntry(" -> ShutdownPriv achieved");

		// Shutdown pc
		ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG,0);
		loggingFile->writeEntry(" -> AdminShutdown performed\n");
    loggingFile->writeTmpEntry();
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

bool isRemoteUserLoggedIn() {
	PWTS_SESSION_INFO ppSessionInfo = NULL;
	DWORD pCount;

	BOOL bRet = WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,0,1,&ppSessionInfo,&pCount);

	if (!bRet) {
		return false;
	}

	for(DWORD idx=0;idx<pCount;idx++) {
		if (ppSessionInfo[idx].State == WTSActive)
			return true;
	}

	return false;
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
