// Usage
//
//    $ MinimalInject.exe EXE [DLL...]
//
// Examples
//
//    $ MinimalInject.exe a.exe b.dll c.dll

// THANKS https://github.com/mewrev/inject and Adrian Herrera

#include <stdio.h>
#include <windows.h>
#include <Shlwapi.h>

// We must add this header file to support writing to S2E's logs. s2e.h resides
// in the libcommon project, so the libcommon project must be added as a
// dependency to the malware-inject project
#define USER_APP
#include <s2e/s2e.h>

/// Maximum message length to write to S2E debug log
#define S2E_MSG_LEN 512

/// Maximum path length
#define MAX_PATH_LEN 256

/// S2E version number, or 0 if not running in S2E mode
static INT s2eVersion = 0;

///
/// Write a message to the S2E log (or stdout).
///
static void Message(LPCSTR fmt, ...) {
	CHAR message[S2E_MSG_LEN];
	va_list args;

	va_start(args, fmt);
	vsnprintf(message, S2E_MSG_LEN, fmt, args);
	va_end(args);

	if (s2eVersion) {
		S2EMessageFmt("[malware-inject] %s", message);
	}
	else {
		printf("[malware-inject] %s", message);
	}
}

static void GetFullPath(const char* path, char* fullPath) {
	if (!path) {
		Message("Path has not been provided\n");
		exit(1);
	}

	if (!PathFileExistsA(path)) {
		Message("Invalid path %s has been provided\n", path);
		exit(1);
	}

	if (!GetFullPathNameA(path, MAX_PATH, fullPath, NULL)) {
		Message("Unable to get full path of %s\n", fullPath);
		exit(1);
	}
}

int main(int argc, char **argv) {
	int i, len;
	char *exe_path, *lib_path;
	char full_exe_path[MAX_PATH];
	char full_lib_path[MAX_PATH];
	void *page;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	HANDLE hThread;

	// Used by the Message function to decide where to write output to
	s2eVersion = S2EGetVersion();

	// Print usage.
	if (argc < 2) {
		Message("Usage: inject EXE [DLL...]\n");
		Message("Inject an ordered list of shared libraries into the address space of a binary executable.\n");
		return 1;
	}

	// Execute the process in suspended mode.
	exe_path = argv[1];
	GetFullPath(exe_path, full_exe_path);
	si.cb = sizeof(STARTUPINFO);
	if (!CreateProcessA(NULL, full_exe_path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		Message("CreateProcess(\"%s\") failed; error code = 0x%08X\n", full_exe_path, GetLastError());
		return 1;
	}

	// Allocate a page in memory for the arguments of LoadLibrary.
	page = VirtualAllocEx(pi.hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (page == NULL) {
		Message("VirtualAllocEx failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	// Inject the ordered list of shared libraries into the address space of the
	// process.
	for (i = 2; i < argc; i++) {
		// Verify path length.
		lib_path = argv[i];
		GetFullPath(lib_path, full_lib_path);
		len = strlen(full_lib_path) + 1;
		if (len > MAX_PATH) {
			Message("path length (%d) exceeds MAX_PATH (%d).\n", len, MAX_PATH);
			return 1;
		}
		if (GetFileAttributesA(full_lib_path) == INVALID_FILE_ATTRIBUTES) {
			Message("unable to locate library (%s).\n", full_lib_path);
			return 1;
		}

		// Write library path to the page used for LoadLibrary arguments.
		if (WriteProcessMemory(pi.hProcess, page, full_lib_path, len, NULL) == 0) {
			Message("WriteProcessMemory failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Inject the shared library into the address space of the process,
		// through a call to LoadLibrary.
		hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, page, 0, NULL);
		if (hThread == NULL) {
			Message("CreateRemoteThread failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Wait for DllMain to return.
		if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
			Message("WaitForSingleObject failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Cleanup.
		CloseHandle(hThread);
	}

	// Resume the execution of the process, once all libraries have been injected
	// into its address space.
	if (ResumeThread(pi.hThread) == -1) {
		Message("ResumeThread failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	if (WaitForSingleObject(pi.hThread, INFINITE) == WAIT_FAILED) {
		Message("WaitForSingleObject failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	// Cleanup.
	VirtualFreeEx(pi.hProcess, page, MAX_PATH, MEM_RELEASE);
	CloseHandle(pi.hProcess);
	return 0;
}