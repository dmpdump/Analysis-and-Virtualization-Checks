/*
 * Disclaimer:
 * This code was created for educational purposes only.
 * The author does not take responsibility for any misuse 
 * or unintended consequences arising from its application.
 * Users are encouraged to exercise caution and adhere to 
 * all relevant laws and regulations when utilizing this code.
 */

#include <Windows.h>
#include <intrin.h>
#include <winternl.h>
#include <iostream>
#include <windef.h>
#include <WinUser.h>
#include <vector>
#include <tlhelp32.h>
#include <string>

using namespace std;

void CheckCpuId(void)
{
	int cpuInfo[4] = {0};
	int hypervbit = 0;

	__cpuid(cpuInfo, 1);
	hypervbit = (cpuInfo[2] >> 31 & 1);
	
	if (hypervbit)
		cout << "[x] Running on a VM according to CPUID." << endl;
	else
		cout << "[+] Not running on a VM according to CPUID." << endl;

}

BOOL IsBeingDebuggedPEB()
{
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif 
	
	if (pPeb->BeingDebugged == 1)
		cout << "[x] It is being debugged according to PEB BeingDebugged." << endl;
	else
		cout << "[+] Not being debugged according to PEB BeingDebugged." << endl;
	return 0;
	
}

BOOL FindTools()
{
	const std::vector<std::string> vWindowClasses = { "antidbg", "ID", "ObsidianGUI", "x64dbg", "Rock Debugger", "SunAwtFrame","Qt5QWindowIcon","WinDbgFrameClass", "Zeta Debugger"};
	
	for (auto& sWndClass : vWindowClasses)
	{
		if (NULL != FindWindowA(sWndClass.c_str(), NULL))
			return TRUE;
	}
	return FALSE;

}

BOOL RunningProcesses()
{
	HANDLE hSnapShot;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	const std::vector<std::wstring> vAnalysisProcess = { L"notepad.exe", L"othertools.exe"};

	BOOL Ret = Process32First(hSnapShot, &pe32);

	do
	{

		for (const auto& proc : vAnalysisProcess)
		{
			if (0 == lstrcmpiW(proc.c_str(), pe32.szExeFile))
			CloseHandle(hSnapShot);
			return TRUE;
		}

	} while (Process32Next(hSnapShot, &pe32));

	
	CloseHandle(hSnapShot);
	
	return FALSE;
}

int main()
{
	
	CheckCpuId();    //check for hypervisor with cpuid
	IsBeingDebuggedPEB();   //check for BeingDebugged bit in PEB
	

	if (RunningProcesses()) // check analysis tools based on running processes
		wcout << "[x] Analysis Process Found based on running processes." << endl;
	else
		wcout << "[+] No analysis tools found based on running processes." << endl;

	if (FindTools())     //check analysis tools in open windows
		wcout << "[x] Analysis tools found based on open windows." << endl;
	else
		wcout << "[+] No analysis tools found based on open windows." << endl;
	
	return 0;

}
