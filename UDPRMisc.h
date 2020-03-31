#pragma once

/// STD
#include <atomic>

/// WINDOWS
#include <WinSock2.h>

namespace UDPR
{
	static bool RetryRecv(int errCode)
	{
		switch (errCode)
		{
		case WSAENETRESET:
		case WSAENETDOWN:
			return true;
		default:
			return false;
		}
		
		return false;
	}

	static bool RetrySendTo(int errCode)
	{
		switch (errCode)
		{
		case WSAENETDOWN:
		case WSAENETRESET:
		case WSAENOBUFS:
		case WSAEHOSTUNREACH:
		case WSAENETUNREACH:
		case WSAETIMEDOUT:
			return true;
		default:
			return false;
		}

		return false;
	}

	template<class T>
	static bool DataAvailable(SOCKET sock, const timeval& timeout, T* owner)
	{
		fd_set fd;
		ZeroMemory(&fd, sizeof(fd));

		fd.fd_count    = 1;
		fd.fd_array[0] = sock;

		int res = select(NULL, &fd, nullptr, nullptr, &timeout);

		if (res == SOCKET_ERROR)
		{
			owner->InitEx("Failed the select.", WSAGetLastError());
			return false;
		}

		return res != 0;
	}

	template<class T>
	static bool WaitForData(SOCKET sock, const timeval& timeout, T* owner,
							const std::atomic_bool& bShouldStop, const std::atomic_bool& bExInit)
	{
		while (!DataAvailable(sock, timeout, owner))
		{
			if (bExInit || bShouldStop)
			{
				return false;
			}
		}

		return true;
	}

	template<class T>
	static bool ReceiveData(SOCKET sock, const timeval& timeout, T* owner,
							const std::atomic_bool& bShouldStop, const std::atomic_bool& bExInit,
							char* data, int len, int flags, sockaddr* from, int* fromlen, int* packetLen = nullptr)
	{
		if (!WaitForData(sock, timeout, owner, bShouldStop, bExInit))
		{
			return false;
		}

	BEGIN:
		if (bShouldStop) { return false; }

		int res;
		if ((res = recvfrom(sock, data, len, flags, from, fromlen)) == SOCKET_ERROR)
		{
			int err = WSAGetLastError();
			if (RetryRecv(err))
			{
				goto BEGIN;
			}
			else
			{
				owner->InitEx("Failed the recvfrom.", err);
				return false;
			}
		}

		if (packetLen != nullptr)
		{
			(*packetLen) = res;
		}

		return true;
	}

	template<class T>
	static bool SendData(SOCKET sock, T* owner,
						 const std::atomic_bool& bShouldStop, const char* data, int len, 
						 int flags, const sockaddr* to, int tolen)
	{
	BEGIN:
		if (bShouldStop) { return false; }

		if (sendto(sock, data, len, flags, to, tolen) == SOCKET_ERROR)
		{
			int err = WSAGetLastError();
			if (RetrySendTo(err))
			{
				goto BEGIN;
			}
			else
			{
				owner->InitEx("Failed the sendto.", err);
				return false;
			}
		}

		return true;
	}
}
