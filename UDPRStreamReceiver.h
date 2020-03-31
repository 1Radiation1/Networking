#pragma once

/// STD
#include <memory>
#include <thread>
#include <atomic>
#include <cstdint>
#include <vector>
#include <cstring>
#include <string>

/// WINDOWS
#include <WinSock2.h>

/// CUSTOM
#include "UDPRDebugHeaders.h"
#include "UDPRMisc.h"
#include "UDPRStreamSender.h"

namespace UDPR
{
	template<class TStream>
	class StreamReceiver
	{
	public:
		StreamReceiver(TStream* _stream, const SOCKADDR_IN& _peerAddr, const timeval& _timeout = { 0, 500 * 1000 }) :
			peer(INVALID_SOCKET),
			peerAddr { _peerAddr },
			packet {  },
			timeout(_timeout),
			packetID(0ULL),
			pos(0ULL),
			stream(_stream),
			bShouldStop(false),
			bFinished(false),
			process(&StreamReceiver::Receive, this)
		{
		}

		~StreamReceiver()
		{
			Stop();
		}

		void Stop()
		{
			if (process.joinable())
			{
				bShouldStop = true;
				process.join();
				bShouldStop = false;
			}
		}

	private:
		void Receive()
		{
			/// WSAStartup.
			{
				WSADATA wsaData;
				ZeroMemory(&wsaData, sizeof(wsaData));

				if (int err; (err = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
				{
					return InitEx("Failed the startup.", err);
				}
			}
			
			HandShake();

			if (!bExInit)
			{
				ReceiveStream();
			}


			Cleanup();

			/// WSACleanup.
			{
				while (WSACleanup() != 0)
				{
					int err = WSAGetLastError();
					if ((err == WSANOTINITIALISED) || (err == WSAENETDOWN))
					{
						break;
					}
				}
			}

			bFinished = true;
		}

	private:
		void Cleanup()
		{
			if (stream.get() != nullptr)
			{
				delete stream.release();
			}

			if (peer != INVALID_SOCKET)
			{
				closesocket(peer);
				peer = INVALID_SOCKET;
			}
		}

		template<class T>
		friend bool UDPR::DataAvailable(SOCKET sock, const timeval& timeout, T* owner);

		template<class T>
		friend bool UDPR::WaitForData(SOCKET sock, const timeval& timeout, T* owner,
									  const std::atomic_bool& bShouldStop, const std::atomic_bool& bExInit);

		template<class T>
		friend bool UDPR::ReceiveData(SOCKET sock, const timeval& timeout, T* owner,
									  const std::atomic_bool& bShouldStop, const std::atomic_bool& bExInit,
									  char* data, int len, int flags, sockaddr* from, int* fromlen, int* packetLen);

		template<class T>
		friend bool UDPR::SendData(SOCKET sock, T* owner,
								   const std::atomic_bool& bShouldStop, const char* data, int len, 
								   int flags, const sockaddr* to, int tolen);

	private:
		void HandShake()
		{
			if ((peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
			{
				return InitEx("Failed the socket.", WSAGetLastError());
			}

		RETRY_SENDHANDSHAKE:
			do
			{
				SendHandshake();

				if (bExInit) 
				{ 
					break; 
				}
			}
			while (!bShouldStop && !DataAvailable(peer, timeout, this) && !bExInit);

			if (!bExInit && !bShouldStop)
			{
				if (!ReceiveHandshake())
				{
					if (!bExInit && !bShouldStop)
					{
						goto RETRY_SENDHANDSHAKE;
					}
				}
			}
		}

		void SendHandshake()
		{
			do
			{
				if (!SendData(peer, this, bShouldStop, reinterpret_cast<const char*>(&StreamSender<class T>::INM_handshake),
							  sizeof(uint8_t), NULL, reinterpret_cast<const sockaddr*>(&peerAddr), sizeof(peerAddr)))
				{
					return;
				}
			}
			while(!bShouldStop && !DataAvailable(peer, timeout, this) && !bExInit);
		}

		bool ReceiveHandshake()
		{
			SOCKADDR_IN from;
			ZeroMemory(&from, sizeof(from));

			int fromlen = sizeof(from);

			BYTE data[sizeof(uint8_t) + sizeof(uint16_t)];

		RETRY_RECV:
			if (!ReceiveData(peer, timeout, this, bShouldStop, bExInit, 
							 reinterpret_cast<char*>(data), sizeof(data), NULL, 
							 reinterpret_cast<sockaddr*>(&from), &fromlen))
			{
				return false;
			}

			if (from.sin_addr.S_un.S_addr != peerAddr.sin_addr.S_un.S_addr)
			{
				goto RETRY_RECV;
			}

			{
				uint8_t msgType;
				std::memcpy(reinterpret_cast<void*>(&msgType), 
							reinterpret_cast<const void*>(data), sizeof(uint8_t));

				if (msgType != StreamSender<class T>::OUTM_handshake)
				{
					InitEx("Invalid handshake.", -1);
					return false;
				}
			}
			{
				uint16_t packetSz;
				std::memcpy(reinterpret_cast<void*>(&packetSz),
							reinterpret_cast<const void*>(data + sizeof(uint8_t)), sizeof(uint16_t));

				packet = std::vector<BYTE>(packetSz);
			}

			return true;
		}

	private:
		void ReceiveStream()
		{

		BEGIN_SENDREQ:
			// Sending the request.
			if (bShouldStop) { return; }

			{

				// 1 byte for message type, 8 bytes for the ID, 8 bytes for the position, 2 bytes for the length.
				BYTE reqData[sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t)];
			
				int offset = 0;
				std::memcpy(reinterpret_cast<void*>(reqData + offset), 
							reinterpret_cast<const void*>(&StreamSender<class T>::INM_request), sizeof(uint8_t));
				offset += sizeof(uint8_t);
			
				std::memcpy(reinterpret_cast<void*>(reqData + offset),
							reinterpret_cast<const void*>(&packetID), sizeof(uint64_t));
				offset += sizeof(uint64_t);

				std::memcpy(reinterpret_cast<void*>(reqData + offset),
							reinterpret_cast<const void*>(&pos), sizeof(uint64_t));
				offset += sizeof(uint64_t);

				uint16_t auxSz = static_cast<uint16_t>(packet.size());
				std::memcpy(reinterpret_cast<void*>(reqData + offset),
							reinterpret_cast<const void*>(&auxSz), sizeof(uint16_t));
				offset += sizeof(uint16_t);


				if (!SendData(peer, this, bShouldStop, reinterpret_cast<const char*>(reqData),
							  sizeof(reqData), NULL, reinterpret_cast<const sockaddr*>(&peerAddr), sizeof(peerAddr)))
				{
					return;
				}
			}

			// Receiving the data requested.
			SOCKADDR_IN from;
			ZeroMemory(&from, sizeof(from));
			int fromlen = sizeof(from);

			int packetLen;
			if (!ReceiveData(peer, timeout, this, bShouldStop, bExInit,
							 reinterpret_cast<char*>(packet.data()), (int) packet.size(), NULL,
							 reinterpret_cast<sockaddr*>(&from), &fromlen, &packetLen))
			{
				return;
			}

			if (from.sin_addr.S_un.S_addr != peerAddr.sin_addr.S_un.S_addr)
			{
				goto BEGIN_SENDREQ;
			}

			// Decyphering data.
			size_t offset = 0;
			{
				uint8_t msgType;
				std::memcpy(reinterpret_cast<void*>(&msgType), 
							reinterpret_cast<const void*>(packet.data()), sizeof(uint8_t));
				offset += sizeof(uint8_t);

				if (msgType != StreamSender<class T>::OUTM_payload)
				{
					goto BEGIN_SENDREQ;
				}

				uint64_t reqID;
				std::memcpy(reinterpret_cast<void*>(&reqID), 
							reinterpret_cast<const void*>(packet.data() + offset), sizeof(uint64_t));
				offset += sizeof(uint64_t);

				if (reqID != packetID)
				{
					goto BEGIN_SENDREQ;
				}
				else
				{
					++packetID;
				}
			}

			try
			{
				stream->write(packet.data() + offset, packetLen - offset);
			}
			catch (const std::exception& ex)
			{
				std::string err = std::string("Failed some stream operation with message:'") + std::string(ex.what()) + std::string("'");
				return InitEx(err, -1);
			}
			
			pos += packetLen - offset;

			if (packetLen == packet.size())
			{
				goto BEGIN_SENDREQ;
			}
		}

	private:
		SOCKET peer;
		SOCKADDR_IN peerAddr;

		std::vector<BYTE> packet;
		const timeval timeout;
		uint64_t packetID;
		uint64_t pos;

	private:
		// The stream, where received data will be written.
		std::unique_ptr<TStream> stream;

		// For the thread.
		std::atomic_bool bShouldStop;
		std::atomic_bool bFinished;
		std::thread process;

	private:
		// Exception handling.
		std::string errStr = "";
		int errCode = 0;
		std::atomic_bool bExInit = false;

	private:
		void InitEx(const std::string& _errStr, int _errCode)
		{
			errStr = _errStr;
			errCode = _errCode;
			bExInit = true;
		}

	public:
		/// Misc (e.g. getters, setters, status functions etc.).

		FORCEINLINE bool ErrorOccured() const { return bExInit; }

		FORCEINLINE const std::string& GetErrorString() const { return errStr; }

		FORCEINLINE const int GetErrorCode() const { return errCode; }

		FORCEINLINE const SOCKADDR_IN GetPeerAddress() const { return peerAddr; }
		
		FORCEINLINE bool IsRunning() const { return !bFinished; }
	};
}
