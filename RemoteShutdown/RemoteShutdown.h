#pragma once;

// Use windows function available from XP and forward
#define _WIN32_WINNT NTDDI_WINXP

#include <windows.h>
#include <wtsapi32.h>
#include <cstdio>

#include "GlobalConst.h"
#include "Network.h"
#include "ServiceHelper.h"
#include "ChallengeResponse.h"
#include "ProtectedStorage.h"
#include "sha256.h"
#include "Logger.h"

using namespace std;

std::string MessageRecieved(const char* message, in_addr ip);