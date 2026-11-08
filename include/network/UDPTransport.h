#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace network {

struct Endpoint {
	std::string address;
	std::uint16_t port;
};

struct Datagram {
	std::vector<std::uint8_t> data;
	Endpoint sender;
};

class UDPTransport {
	public:
		UDPTransport();
		~UDPTransport();

		UDPTransport(const UDPTransport&) = delete;
		UDPTransport& operator=(const UDPTransport&) = delete;

		void sendTo(
			std::span<const std::uint8_t> data,
			const Endpoint& destination
		);

		std::optional<Datagram> receiveFrom();

	private:
		struct Impl;
		std::unique_ptr<Impl> impl;
};

}