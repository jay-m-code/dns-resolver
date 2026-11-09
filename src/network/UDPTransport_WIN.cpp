#include "network/UDPTransport.h"

#include <winsock2.h>
#include <ws2tcpip.h> 
#include <system_error>
#include <stdexcept>
#include <array>
#include <utility>

namespace {
    sockaddr_in toSockaddr(const network::Endpoint& endpoint) {
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_port = htons(endpoint.port);
        int result = inet_pton(AF_INET, endpoint.address.c_str(), &address.sin_addr);

        switch (result)
        {
        case -1:
            throw std::system_error(WSAGetLastError(), std::system_category(), "Failed to set IP address!");
        case 0:
            throw std::invalid_argument("Invalid IP address!");
        default:
            break;
        }

        return address;
    }

    network::Endpoint fromSockAddr(const sockaddr_in& address) {
        std::uint16_t port = ntohs(address.sin_port);
        std::array<char, INET_ADDRSTRLEN> ipBuffer{};
        const char* IP = inet_ntop(AF_INET, &address.sin_addr, ipBuffer.data(), ipBuffer.size());
        if (IP == nullptr) {
            throw std::system_error(WSAGetLastError(), std::system_category(), "failed to retrieve IP");
        }

        return {IP, port};
    }
}

namespace network {

struct UDPTransport::Impl {
    SOCKET socketHandle = INVALID_SOCKET;
    std::array<std::uint8_t, 65507> buffer;

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    Impl() {
        WSADATA wsadata;
        int result = WSAStartup(MAKEWORD(2,2), &wsadata);

        if (result != 0) {
            throw std::system_error(result, std::system_category(), "Failed to start WSA!");
        }

        socketHandle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        
        if (socketHandle == INVALID_SOCKET) {
            int error = WSAGetLastError();
            WSACleanup();
            throw std::system_error(error, std::system_category(), "Failed to create socket!");
        }

        u_long enabledMode = 1;
        int modeResult = ioctlsocket(socketHandle, FIONBIO, &enabledMode);

        if (modeResult == SOCKET_ERROR) {
            int error = WSAGetLastError();
            closesocket(socketHandle);
            WSACleanup();
            throw std::system_error(error, std::system_category(), "Failed to configure socket!");
        }
    }

    ~Impl() {
        closesocket(socketHandle);
        WSACleanup();
    }
};

UDPTransport::UDPTransport(): impl(std::make_unique<Impl>()) {}

UDPTransport::~UDPTransport() = default;

void UDPTransport::sendTo(std::span<const std::uint8_t> data, const Endpoint& destination) {
    sockaddr_in address = toSockaddr(destination);  

    if (data.size() > 65507) {
        throw std::invalid_argument("Data size is too large!");
    }

    int sendResult = sendto(
        impl->socketHandle,
        reinterpret_cast<const char*>(data.data()),
        static_cast<int>(data.size()),
        0,
        reinterpret_cast<const sockaddr*>(&address),
        static_cast<int>(sizeof(address))
    );

    if (sendResult == SOCKET_ERROR) {
        throw std::system_error(WSAGetLastError(), std::system_category(), "Failed to send data!");
    }
}

std::optional<Datagram> UDPTransport::receiveFrom() {
    sockaddr_in sender {};
    int size = sizeof(sender);

    int receivedSize = recvfrom(impl->socketHandle, reinterpret_cast<char*>(impl->buffer.data()), static_cast<int>(impl->buffer.size()), 0, reinterpret_cast<sockaddr*>(&sender), &size);

    if (receivedSize == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            return std::nullopt;
        }
        throw std::system_error(error, std::system_category(), "Failed to receive data!");
    }

    std::vector<uint8_t> data(impl->buffer.begin(), impl->buffer.begin() + receivedSize);

    Endpoint endpoint = fromSockAddr(sender);
    Datagram datagram {std::move(data), endpoint};

    return datagram;
}

void UDPTransport::bind(const Endpoint& localAddress) {
    sockaddr_in address = toSockaddr(localAddress);

    int bindResult = ::bind(impl->socketHandle, reinterpret_cast<const sockaddr*>(&address), static_cast<int>(sizeof(address)));
    if (bindResult == SOCKET_ERROR) {
        throw std::system_error(WSAGetLastError(), std::system_category(), "Failed to bind!");
    }
}

Endpoint UDPTransport::localEndpoint() const {
    sockaddr_in localAddress {};
    int size = sizeof(localAddress);

    int result = getsockname(impl->socketHandle, reinterpret_cast<sockaddr*>(&localAddress), &size);

    if (result == SOCKET_ERROR) {
        throw std::system_error(WSAGetLastError(), std::system_category(), "Failed to get local endpoint!");
    }

    return fromSockAddr(localAddress);
}

}