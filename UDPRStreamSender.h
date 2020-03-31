#pragma once

/// STD
#include <memory>
#include <utility>
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

namespace UDPR
{
	template<class TStream>
	class StreamSender
	{
	public:
		/// Outgoing messages.
		static const uint8_t OUTM_handshake = 0;
		static const uint8_t OUTM_payload   = 1;

		/// Incoming messages.
		static const uint8_t INM_handshake = 0;
		static const uint8_t INM_request   = 1;

	public:
		StreamSender(TStream* _stream, uint16_t _port, uint16_t _packetSz = 508, const timeval& _timeout = { 0, 500 * 1000 }) :
			packet(_packetSz),
			peer(INVALID_SOCKET),
			peerAddr {  },
			packetSz(_packetSz),
			port(_port),
			timeout(_timeout),
			stream(_stream),
			bShouldStop(false),
			bAcknowledged(false),
			bFinished(false),
			process(&StreamSender::Send, this)
		{
		}

		~StreamSender()
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

		void Send()
		{
			/// WSAStartup.
			{
				WSADATA wsaData;
				ZeroMemory(&wsaData, sizeof(wsaData));

				if (int err; (err = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
				{
					return InitEx("Failed the WSAStartup.", err);
				}
			}

			HandShake();

			if (!bExInit)
			{
				while (!SendStream())
				{
					if (bExInit) { break; }

					SendHandshake();

					if (bExInit) { break; }
				}
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
			// Creating the socket.
			if ((peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
			{
				return InitEx("Failed the socket.", WSAGetLastError());
			}

			// Binding the socket.
			SOCKADDR_IN anyAddr;
			ZeroMemory(&anyAddr, sizeof(anyAddr));

			anyAddr.sin_family			 = AF_INET;
			anyAddr.sin_port			 = htons(port);
			anyAddr.sin_addr.S_un.S_addr = htonl(ADDR_ANY);

			if (bind(peer, reinterpret_cast<const sockaddr*>(&anyAddr), sizeof(anyAddr)) == SOCKET_ERROR)
			{
				return InitEx("Failed the bind.", WSAGetLastError());
			}

			ReceiveHandshake();

			if (!bExInit)
			{
				SendHandshake();
			}
		}

		void ReceiveHandshake()
		{
			ZeroMemory(&peerAddr, sizeof(peerAddr));
			int peerAddrSz = sizeof(peerAddr);
			uint8_t msgType;
			if (ReceiveData(peer, timeout, this, bShouldStop, bExInit,
							reinterpret_cast<char*>(&msgType), sizeof(uint8_t),
							NULL, reinterpret_cast<sockaddr*>(&peerAddr), &peerAddrSz))
			{
				if (msgType != INM_handshake)
				{
					return InitEx("Corrupt handshake message.", -1);
				}
			}
		}

		void SendHandshake()
		{
			BYTE data[sizeof(uint8_t) + sizeof(uint16_t)];
			// First byte for message type.
			std::memcpy(reinterpret_cast<void*>(data), 
						reinterpret_cast<const void*>(&OUTM_handshake), sizeof(uint8_t));

			// Next two bytes for the MTU.
			std::memcpy(reinterpret_cast<void*>(data + sizeof(uint8_t)), 
						reinterpret_cast<const void*>(&packetSz), sizeof(uint16_t));

			do
			{
				SendData(peer, this, bShouldStop,
						 reinterpret_cast<const char*>(data), 
						 sizeof(data), NULL, reinterpret_cast<const sockaddr*>(&peerAddr), sizeof(peerAddr));
			}
			while (!bShouldStop && !DataAvailable(peer, timeout, this) && !bExInit);
		}

	private:
		// Returns true, if succesful and false otherwise.
		bool SendStream()
		{
			SOCKADDR_IN auxAddr;
			ZeroMemory(&auxAddr, sizeof(auxAddr));
			int auxAddrSz = sizeof(auxAddr);

			// Begin receiving the request.
		BEGIN_RECVREQ:
			if (bShouldStop) 
			{
				return true; 
			}

			// 1 byte for message type, 8 bytes for the ID, 8 bytes for the position, 2 bytes for the length.
			BYTE reqData[sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t)];

			if (ReceiveData(peer, timeout, this, bShouldStop, bExInit,
							reinterpret_cast<char*>(reqData), sizeof(reqData),
							NULL, reinterpret_cast<sockaddr*>(&auxAddr), &auxAddrSz))
			{
				// If the actual peer sent you a message, then you have been noticed.
				if (auxAddr.sin_addr.S_un.S_addr == peerAddr.sin_addr.S_un.S_addr)
				{
					bAcknowledged = true;
				}
				else
				{
					if (bAcknowledged)
					{
						goto BEGIN_RECVREQ;
					}
					else
					{
						return false;
					}
				}
			}
			else
			{
				return false; 
			}

			uint64_t packetID, pos;
			uint16_t packetLen;
			uint8_t msgType;

			// Decyphering the request.
			{
				int offset = 0;
				std::memcpy(reinterpret_cast<void*>(&msgType), reinterpret_cast<const void*>(reqData + offset), sizeof(uint8_t));
				offset += sizeof(uint8_t);
				std::memcpy(reinterpret_cast<void*>(&packetID), reinterpret_cast<const void*>(reqData + offset), sizeof(uint64_t));
				offset += sizeof(uint64_t);
				std::memcpy(reinterpret_cast<void*>(&pos), reinterpret_cast<const void*>(reqData + offset), sizeof(uint64_t));
				offset += sizeof(uint64_t);
				std::memcpy(reinterpret_cast<void*>(&packetLen), reinterpret_cast<const void*>(reqData + offset), sizeof(uint16_t));
				offset += sizeof(uint16_t);
			}

			// Verifing the integrity of the request.
			{
				if ((msgType != INM_request) || (packetLen > packetSz))
				{
					InitEx("Corrupt request.", -1);
					return false;
				}
			}

			// Setting the message type.
			std::memcpy(reinterpret_cast<void*>(packet.data()),
						reinterpret_cast<const void*>(&OUTM_payload), sizeof(uint8_t));
			// Setting the packet ID.
			std::memcpy(reinterpret_cast<void*>(packet.data() + sizeof(uint8_t)), 
						reinterpret_cast<const void*>(&packetID), sizeof(uint64_t));

			// Reading data from the stream.
			uint16_t byteCount = packetLen;
			try
			{
				stream->seekg(pos);
				stream->read(packet.data() + (sizeof(uint64_t) + sizeof(uint8_t)), packetLen - (sizeof(uint64_t) + sizeof(uint8_t)));

				if (stream->eof())
				{
					byteCount = static_cast<decltype(byteCount)>(sizeof(uint64_t) + sizeof(uint8_t));
					byteCount += static_cast<decltype(byteCount)>(stream->gcount());
					stream->clear();
				}
			}
			catch (const std::exception& ex)
			{
				std::string err = std::string("Failed some stream operation with message:'") + std::string(ex.what()) + std::string("'");
				InitEx(err, -1);
				return false;
			}

			if (!SendData(peer, this, bShouldStop,
						  reinterpret_cast<const char*>(packet.data()), byteCount, 
						  NULL, reinterpret_cast<const sockaddr*>(&peerAddr), sizeof(peerAddr)))
			{
				return false;
			}

			goto BEGIN_RECVREQ;
		}

	private:
		// Packet that will be filled and sent.
		std::vector<BYTE> packet;

		// Networking objects.
		SOCKET peer;
		SOCKADDR_IN peerAddr;

		const uint16_t packetSz;
		const uint16_t port;
		const timeval timeout;

	private:
		// The stream that will be sent.
		std::unique_ptr<TStream> stream;

		// For the thread.
		std::atomic_bool bShouldStop;
		std::atomic_bool bAcknowledged;
		std::atomic_bool bFinished;
		std::thread process;

	private:
		// Exception handling.
		void InitEx(const std::string& _errStr, int _errCode)
		{
		#ifdef _DEBUG
			if (bExInit) 
			{
				assert("Trying to override the exception.\n" == NULL);
			}
		#endif

			errStr  = _errStr;
			errCode = _errCode;
			bExInit = true;
		}

	private:
		// For the exception.
		std::atomic_bool bExInit = false;
		std::string errStr = "";
		int errCode = 0;

	public:
		/// Misc (e.g. getters, setters, status functions etc.).
		
		FORCEINLINE bool ErrorOccured() const { return bExInit; }

		FORCEINLINE bool IsRunning() const { return !bFinished; }

		FORCEINLINE const std::string& GetErrorString() const { return errStr; }
		
		FORCEINLINE int GetErrorCode() const { return errCode; }

		FORCEINLINE uint16_t GetPort() const { return port; }

		FORCEINLINE uint16_t GetPacketSize() const { return packetSz; }

		FORCEINLINE timeval GetTimeout() const { return timeout; }
	};
}

