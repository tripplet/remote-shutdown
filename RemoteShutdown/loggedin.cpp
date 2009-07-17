#define _WIN32_WINNT NTDDI_WINXP // Wir verwenden Funktionen die ab Windows XP verfügbar sind

#include <windows.h>
#include <ntstatus.h>
#include <ntsecapi.h>

#include <cstdlib>
#include <iostream>

#include <fstream>


using namespace std;

/*VOID GetSessionData(PLUID session)
{
  PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
  NTSTATUS retval;
  WCHAR buffer[256];
  WCHAR *usBuffer;
  int usLength;

  // Check for a valid session.
  if (!session ) {
    wprintf(L"Error - Invalid logon session identifier.\n");
    return;
  }
  // Get the session information.
  retval = LsaGetLogonSessionData (session, &sessionData);
  if (retval != STATUS_SUCCESS) {
    // An error occurred. Tell the world.
    wprintf (L"LsaGetLogonSessionData failed %lu \n",
      LsaNtStatusToWinError(retval));
    // If session information was returned, free it.
    if (sessionData) {
      LsaFreeReturnBuffer(sessionData);
    }
    return;
  } 
  // Determine whether there is session data to parse. 
  if (!sessionData) { // no data for session
    wprintf(L"Invalid logon session data. \n");
    return;
  }
  if (sessionData->UserName.Buffer != NULL) {
    // Get the user name.
    usBuffer = (sessionData->UserName).Buffer;
    usLength = (sessionData->UserName).Length;
    if(usLength < 256)
    {
        wcsncpy_s (buffer, 256, usBuffer, usLength);
        wcscat_s (buffer, 256, L"");
    }
    else
    {
        wprintf(L"\nUser name too long for buffer. Exiting program.");
        exit(1);
    }
    
    wprintf (L"user %s was authenticated ",buffer);
  } else {
    wprintf (L"\nMissing user name.\n");
    LsaFreeReturnBuffer(sessionData);
    return;
  }
  if ((SECURITY_LOGON_TYPE) sessionData->LogonType == Interactive) {
    wprintf(L"interactively ");
  }
  if (sessionData->AuthenticationPackage.Buffer != NULL) {
    // Get the authentication package name.
    usBuffer = (sessionData->AuthenticationPackage).Buffer;
    usLength = (sessionData->AuthenticationPackage).Length;
    if(usLength < 256)
    {
        wcsncpy_s (buffer, 256, usBuffer, usLength);
        wcscat_s (buffer, 256, L"");
    }
    else
    {
        wprintf(L"\nAuthentication package too long for buffer."
            L" Exiting program.");
        exit(1);
    }
    wprintf(L"using %s ",buffer);
  } else {
    wprintf (L"\nMissing authentication package.");
    LsaFreeReturnBuffer(sessionData);
    return;
  }
  if (sessionData->LogonDomain.Buffer != NULL) {
    // Get the domain name.
    usBuffer = (sessionData->LogonDomain).Buffer;
    usLength = (sessionData->LogonDomain).Length;
    if(usLength < 256)
    {
        wcsncpy_s (buffer, 256, usBuffer, usLength);
        wcscat_s (buffer, 256, L"");
    }
    else
    {
        wprintf(L"\nLogon domain too long for buffer."
            L" Exiting program.");
        exit(1);
    }
    wprintf(L"in the %s domain.\n",buffer);
  } else {
    wprintf (L"\nMissing authenticating domain information. ");
    LsaFreeReturnBuffer(sessionData);
    return;
  }
  // Free the memory returned by the LSA.
  LsaFreeReturnBuffer(sessionData);
  return;
}
*/
