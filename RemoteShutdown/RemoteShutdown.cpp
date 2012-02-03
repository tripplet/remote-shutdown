#include "RemoteShutdown.h"


/** ########## Global variables ########## **/
HANDLE g_StopEvent;
LogFile *loggingFile;

HANDLE hNetTCPThread;
HANDLE hNetUDPThread;

std::string lastChallange;
time_t lastChallangeTime;

/** ########## Functions ########## **/ 
bool EnableShutdownPrivNT();
bool enableDEP();
bool isUserLoggedOn();
bool isRemoteUserLoggedIn();

void ServiceLoop() {
	loggingFile->writeEntry("Service started");
	hNetTCPThread = StartNetTCPLoopThread(INFORM_PORT);
	hNetUDPThread = StartNetUDPLoopThread(INFORM_PORT);
	//SuspendThread(GetCurrentThread());
  WaitForSingleObject(g_StopEvent,INFINITE);
}

void ServiceQuit() {
	loggingFile->writeEntry("Service quit");
	TerminateThread(hNetTCPThread,0);
	TerminateThread(hNetUDPThread,0);
}

std::string MessageRecieved(const char* message,in_addr ip,int protocol) {
	DWORD bufCharCount = MAX_COMPUTERNAME_LENGTH + 1;
	char *sMessage = new char[strlen(message)+1];

	if (strlen(message)==0)
		return std::string("EMPTY");

  loggingFile->newTmpEntry();
	loggingFile->addTmpEntry("MessageRechived ");
	
	if (protocol==UDP_MESSAGE)
		loggingFile->addTmpEntry("(UDP): ");
	else
		loggingFile->addTmpEntry("(TCP): ");
	
	loggingFile->addTmpEntry(message);
  loggingFile->writeTmpEntry();

	strncpy(sMessage,message,strlen(message)+1);
	strlwr(sMessage);
  

  // challange request
  if (0 == strcmpi(sMessage,"request_shutdown")) {	
    lastChallange = CChallengeResponse::createChallange();
    lastChallangeTime = time(NULL);
    return lastChallange;
  }
  
  // shutdown
  if (0 == strnicmp(sMessage,"shutdown",8)) {
    std::string ret;

    if (!lastChallange.empty() && CChallengeResponse::verifyResponse(lastChallange,std::string(SECRET_SHUTDOWN),std::string(sMessage+9))) {
     
      if (difftime(time(NULL),lastChallangeTime)<=RESPONSE_LIMIT) {
        delete[] sMessage;

        loggingFile->newTmpEntry();
		    loggingFile->addTmpEntry("Shutdown command recognized");

		    if (isUserLoggedOn()) {
			    loggingFile->addTmpEntry(" -> User logged in -> ABORT\n");
          loggingFile->writeTmpEntry();
			    return std::string("USER_LOGGEDIN");
		    }

		    if (isRemoteUserLoggedIn()) {
			    loggingFile->addTmpEntry(" -> RemoteUser logged in -> ABORT\n");
          loggingFile->writeTmpEntry();
			    return std::string("USER_LOGGEDIN");
		    }		
		
		    loggingFile->writeEntry(" -> User not logged in");

		    // get shutdown priv
		    if (!EnableShutdownPrivNT()) {	
			    loggingFile->addTmpEntry(" -> Failed to achieve ShutdownPriv -> ABORT\n");
          loggingFile->writeTmpEntry();
			    return std::string("FAILED");
		    }

		    loggingFile->addTmpEntry(" -> ShutdownPriv achieved");

		    // Shutdown pc
		    ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG,0);
		    loggingFile->addTmpEntry(" -> Shutdown performed");
        loggingFile->writeTmpEntry();
		    return std::string("1");
      }
      else {
        ret = std::string("SLOW");
      }
    }
    else {
      ret = std::string("INVALID");
    }

    lastChallange.clear();
    return ret;
  }


	if (0 == strnicmp(sMessage,"admin_shutdown",14)) {	
		std::string ret;

    if (!lastChallange.empty() && CChallengeResponse::verifyResponse(lastChallange,std::string(SECRET_SHUTDOWN),std::string(sMessage+15))) {
     
      if (difftime(time(NULL),lastChallangeTime)<=RESPONSE_LIMIT) {
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
			    return std::string("FAILED");
		    }

		    loggingFile->addTmpEntry(" -> ShutdownPriv achieved");

		    // Shutdown pc
		    ExitWindowsEx(EWX_POWEROFF | EWX_FORCEIFHUNG,0);
		    loggingFile->writeEntry(" -> AdminShutdown performed\n");
        loggingFile->writeTmpEntry();
		    return std::string("1");
      }
      else {
        ret = std::string("SLOW");
      }
    }
    else {
      ret = std::string("INVALID");
    }

    lastChallange.clear();
    return ret;
	}
  
	return std::string("NOT_RECOGNIZED");
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
