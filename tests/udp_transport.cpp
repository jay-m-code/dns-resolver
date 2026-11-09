#include <gtest/gtest.h>
#include "network/UDPTransport.h"
#include <array>
#include <stdexcept>

TEST(UDPTransport, Loopback) {
    network::UDPTransport receiver;
    network::UDPTransport sender;

    receiver.bind({"127.0.0.1", 0});
    network::Endpoint endpoint = receiver.localEndpoint();

    std::array<std::uint8_t, 2> packet{0xAB, 0xBC};

    sender.sendTo(packet, endpoint);

    std::optional<network::Datagram> datagram;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!datagram && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        datagram = receiver.receiveFrom();
    }

    std::vector<std::uint8_t> expected {0xAB, 0xBC};

    ASSERT_TRUE(datagram.has_value());
    EXPECT_EQ(expected, datagram->data);
    EXPECT_EQ(datagram->sender.address, "127.0.0.1");
}

TEST(UDPTransport, EmptyQueue) {
    network::UDPTransport receiver;

    std::optional<network::Datagram> datagram = receiver.receiveFrom();

    EXPECT_FALSE(datagram.has_value());
}

TEST(UDPTransport, InvalidIP) {
    network::UDPTransport sender;
    std::array<std::uint8_t, 2> packet{0xAB, 0xBC};

    EXPECT_THROW(
        sender.sendTo(packet, {"777.777.777.777", 53}),
        std::invalid_argument
    );
}

TEST(UDPTransport, EmptyData) {
    network::UDPTransport receiver;
    network::UDPTransport sender;

    receiver.bind({"127.0.0.1", 0});
    network::Endpoint endpoint = receiver.localEndpoint();

    std::array<std::uint8_t, 0> packet{};

    sender.sendTo(packet, endpoint);

    std::optional<network::Datagram> datagram;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!datagram && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        datagram = receiver.receiveFrom();
    }


    ASSERT_TRUE(datagram.has_value());
    EXPECT_TRUE(datagram->data.empty());
}