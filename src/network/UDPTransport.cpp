#include "network/UDPTransport.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <system_error>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <array>
#include <utility>

namespace network {

struct UDPTransport::Impl {
	int socketHandle = -1;
    std::array<std::uint8_t, 65507> buffer {};

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    Impl() {
        socketHandle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (socketHandle == -1) {
            throw std::system_error(errno, std::generic_category(), "Failed to create socket!");
        }

        int flags = fcntl(socketHandle, F_GETFL);

        if (flags == -1) {
            int errornumb = errno;
            close(socketHandle);
            throw std::system_error(errornumb, std::generic_category(), "Failed to load socket flags!");
        }

        flags = flags | O_NONBLOCK;
        int result = fcntl(socketHandle, F_SETFL, flags);
        if (result == -1) {
            int errornumb = errno;
            close(socketHandle);
            throw std::system_error(errornumb, std::generic_category(), "Failed to update socket flags!");
        }
    }

    ~Impl() {
        close(socketHandle);
    }
};

UDPTransport::UDPTransport(): impl(std::make_unique<Impl>()) {

}

UDPTransport::~UDPTransport() = default;

void UDPTransport::sendTo(std::span<const std::uint8_t> data, const Endpoint& destination) {
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(destination.port);
    int result = inet_pton(AF_INET, destination.address.c_str(), &address.sin_addr);

    switch (result)
    {
    case -1:
        throw std::system_error(errno, std::generic_category(), "Failed to set IP address!");
    case 0:
        throw std::invalid_argument("Invalid IP address!");
    default:
        break;
    }

    ssize_t sendResult = sendto(
        impl->socketHandle,
        data.data(),
        data.size(),
        0,
        reinterpret_cast<const sockaddr*>(&address),
        sizeof(address)
    );

    if (sendResult == -1) {
        throw std::system_error(errno, std::generic_category(), "Failed to send data!");
    }


}

std::optional<Datagram> UDPTransport::receiveFrom() {
    sockaddr_in sender {};
    socklen_t size = sizeof(sender);

    ssize_t receivedSize = recvfrom(impl->socketHandle, impl->buffer.data(), impl->buffer.size(), 0, reinterpret_cast<sockaddr*>(&sender), &size);

    if (receivedSize == -1 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
        throw std::system_error(errno, std::generic_category(), "Failed to receive data!");
    } else if (receivedSize == -1) {
        return std::nullopt;
    }

    std::vector<uint8_t> data(impl->buffer.begin(), impl->buffer.begin() + receivedSize);
    std::uint16_t port = ntohs(sender.sin_port);

    std::array<char, INET_ADDRSTRLEN> ipBuffer{};
    const char* senderIP = inet_ntop(AF_INET, &sender.sin_addr, ipBuffer.data(), ipBuffer.size());
    
    if (senderIP == nullptr) {
        throw std::system_error(errno, std::generic_category(), "failed to retrieve sender IP");
    }

    Endpoint endpoint {senderIP, port};
    Datagram datagram {std::move(data), endpoint};

    return datagram;
}

void UDPTransport::bind(const Endpoint& localAddress) {
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(localAddress.port);
    int result = inet_pton(AF_INET, localAddress.address.c_str(), &address.sin_addr);

    switch (result)
    {
    case -1:
        throw std::system_error(errno, std::generic_category(), "Failed to set IP address!");
    case 0:
        throw std::invalid_argument("Invalid IP address!");
    default:
        break;
    }

    int bindResult = ::bind(impl->socketHandle, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    if (bindResult == -1) {
        throw std::system_error(errno, std::generic_category(), "Failed to bind!");
    }
}

Endpoint UDPTransport::localEndpoint() const {
    sockaddr_in localAddress {};
    socklen_t size = sizeof(localAddress);

    int result = getsockname(impl->socketHandle, reinterpret_cast<sockaddr*>(&localAddress), &size);

    if (result == -1) {
        throw std::system_error(errno, std::generic_category(), "Failed to get local endpoint!");
    }

    std::uint16_t port = ntohs(localAddress.sin_port);

    std::array<char, INET_ADDRSTRLEN> ipBuffer{};
    const char* localIP = inet_ntop(AF_INET, &localAddress.sin_addr, ipBuffer.data(), ipBuffer.size());
    
    if (localIP == nullptr) {
        throw std::system_error(errno, std::generic_category(), "failed to retrieve local IP");
    }

    Endpoint endpoint {localIP, port};

    return endpoint;
}


}