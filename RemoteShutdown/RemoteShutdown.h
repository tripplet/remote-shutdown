#pragma once;

#define _WIN32_WINNT NTDDI_WINXP // Wir verwenden Funktionen die ab Windows XP verfügbar sind

#include <windows.h>
#include <wtsapi32.h>
#include <cstdio>

#include "GlobalConst.h"
#include "Network.h"
#include "ServiceHelper.h"
#include "ChallengeResponse.h"
#include "ProtectedStorage.h"

using namespace std;

std::string MessageRecieved(const char* message,in_addr ip,int protocol);