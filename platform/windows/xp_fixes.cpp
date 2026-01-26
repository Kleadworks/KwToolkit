#if _WIN32_WINNT < 0x0600
#include <string.h>
#include <stdio.h>
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS // WSAAddressToStringA
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <ntsecapi.h>

// reimplementations of functions that mbedtls needs which don't appear to exist in XP.
// inet functions adapted from https://stackoverflow.com/a/20817001

extern "C" {
	int inet_pton(int af, const char *src, void *dst) {
		struct sockaddr_storage ss;
		int size = sizeof(ss);
		char src_copy[INET6_ADDRSTRLEN+1];

		ZeroMemory(&ss, sizeof(ss));
		strncpy_s(src_copy, sizeof(src_copy), src, INET6_ADDRSTRLEN+1);
		src_copy[INET6_ADDRSTRLEN] = 0;

		if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
			switch(af) {
				case AF_INET:
					*(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
					return 1;
				case AF_INET6:
					*(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
					return 1;
			}
		}
		return 0;
	}

	const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
		struct sockaddr_storage ss;
		unsigned long s = size;

		ZeroMemory(&ss, sizeof(ss));
		ss.ss_family = af;

		switch(af) {
			case AF_INET:
				((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
				break;
			case AF_INET6:
				((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
				break;
			default:
				return NULL;
		}
		
		/* cannot direclty use &size because of strict aliasing rules */
		if (!WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s))
			return dst;
		
		return NULL;
	}
	
	// This is a very basic reimplementation based on a discussion I found:
	// https://github.com/rust-random/getrandom/issues/65
	// Hope this doesn't introduce any ridiculous issues :^)
	NTSTATUS WINAPI BCryptGenRandom(PVOID hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags) {
		if (RtlGenRandom(pbBuffer, cbBuffer)) {
			return 0;
		}
		return 0xC000000D; // STATUS_BAD_ARGUMENT or something iirc
	}
}
#endif