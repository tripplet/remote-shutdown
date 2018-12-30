#include "ServiceHelper.h"

#include <windows.h>
#include <memory>
#include <string>

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;

extern HANDLE g_StopEvent;

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	// Make sure data execution protection is enabled
	SetProcessDEPPolicy(PROCESS_DEP_ENABLE);

	serviceStatus.dwServiceType = SERVICE_WIN32;
	serviceStatus.dwCurrentState = SERVICE_START_PENDING;
	serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	serviceStatus.dwWin32ExitCode = 0;
	serviceStatus.dwServiceSpecificExitCode = 0;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;

	serviceStatusHandle = RegisterServiceCtrlHandler(PROG_NAME, ServiceCtrlHandler);
	if (serviceStatusHandle == nullptr)
	{
		return;
	}

	serviceStatus.dwCurrentState = SERVICE_RUNNING;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;

	if (!SetServiceStatus(serviceStatusHandle, &serviceStatus))
	{
		ServiceQuit();
	}

	ServiceLoop(false);
	ServiceQuit();

	return;
}

void WINAPI ServiceCtrlHandler(DWORD Opcode)
{
	switch (Opcode)
	{
		case SERVICE_CONTROL_PAUSE:
			serviceStatus.dwCurrentState = SERVICE_PAUSED;
			break;

		case SERVICE_CONTROL_CONTINUE:
			serviceStatus.dwCurrentState = SERVICE_RUNNING;
			break;

		case SERVICE_CONTROL_STOP:
			serviceStatus.dwWin32ExitCode = 0;
			serviceStatus.dwCurrentState = SERVICE_STOPPED;
			serviceStatus.dwCheckPoint = 0;
			serviceStatus.dwWaitHint = 0;

			SetServiceStatus(serviceStatusHandle, &serviceStatus);
			SetEvent(g_StopEvent);
			break;

		case SERVICE_CONTROL_INTERROGATE:
			break;
	}

	return;
}

const std::string GetExecutablePath()
{
	char executableFilePath[65536];

	auto const hModule = GetModuleHandle(nullptr);
	auto const filePathLength = GetModuleFileName(hModule, executableFilePath, 65536);

	if (filePathLength > 0 && filePathLength < 65536)
	{
		return std::string(executableFilePath);
	}

	return nullptr;
}

bool InstallCorrespondingService()
{
	bool result = false;
	SC_HANDLE scManager = nullptr, serviceHandle = nullptr;

	try
	{
		auto strPath = GetExecutablePath();

		scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (scManager == nullptr) { throw 0; }

		serviceHandle = CreateService(scManager,
			PROG_NAME, // service name
			PROG_NAME, // service name to display
			SERVICE_ALL_ACCESS, // desired access
			SERVICE_WIN32_OWN_PROCESS, // service type
			SERVICE_AUTO_START, // start type
			SERVICE_ERROR_NORMAL, // error control type
			(LPCTSTR)strPath.c_str(), // service's binary
			nullptr, // no load ordering group
			nullptr, // no tag identifier
			nullptr, // no dependencies
			nullptr, // LocalSystem account
			nullptr); // no password

		if (serviceHandle == nullptr)
		{
			throw 0;
		}

		SERVICE_DESCRIPTION sd;
		sd.lpDescription = "Allow remote shutdown of pc based on shared secret";

		ChangeServiceConfig2(serviceHandle, SERVICE_CONFIG_DESCRIPTION, &sd);
		result = true;
	}
	catch (...)
	{
	}

	// Cleanup
	if (serviceHandle != nullptr) { CloseServiceHandle(serviceHandle); }
	if (scManager != nullptr) { CloseServiceHandle(scManager); }

	return result;
}

bool DeleteCorrespondingService()
{
	bool result = false;
    SERVICE_STATUS status;
	SC_HANDLE scManager = nullptr, serviceHandle = nullptr;

	try
	{
		scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (scManager == nullptr) { throw 0; }

		serviceHandle = OpenService(scManager, PROG_NAME, SERVICE_ALL_ACCESS);
		if (serviceHandle == nullptr) { throw 0; }


		if (!DeleteService(serviceHandle))
		{
			throw 0;
		}
		else
		{
			result = true;
		}

        // Stop the service
        ControlService(serviceHandle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&status);
	}
	catch (...)
	{
	}

	// Cleanup
	if (serviceHandle != nullptr) { CloseServiceHandle(serviceHandle); }
	if (scManager != nullptr) { CloseServiceHandle(scManager); }

	return result;
}

bool StartCorrespondingService()
{
	bool result = false;
	SC_HANDLE scManager = nullptr, serviceHandle = nullptr;

	try
	{
		scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (scManager == nullptr) { throw 0; }

		serviceHandle = OpenService(scManager, PROG_NAME, SERVICE_ALL_ACCESS);
		if (serviceHandle == nullptr) { throw 0; }

		if (!StartService(serviceHandle, 0, nullptr))
		{
			throw 0;
		}
		else
		{
			result = true;
		}
	}
	catch (...)
	{
	}

	// Cleanup
	if (serviceHandle != nullptr) { CloseServiceHandle(serviceHandle); }
	if (scManager != nullptr) { CloseServiceHandle(scManager); }

	return result;
}
