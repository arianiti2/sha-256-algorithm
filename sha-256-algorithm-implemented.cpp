#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>
#include <bitset>


inline uint32_t rightRotate(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

// sha-256 constants
const std::array<uint32_t, 64> k{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// initial hash values
std::array<uint32_t, 8> h{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

std::vector<uint8_t> padMessage(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> paddedMessage = input;
    size_t originalLengthBits = input.size() * 8;

    // append a single '1' bit
    paddedMessage.push_back(0x80);

    // pad with zeros until the message length is congruent to 448 mod 512
    while ((paddedMessage.size() * 8) % 512 != 448) {
        paddedMessage.push_back(0x00);
    }

    // append the original length of the message as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        paddedMessage.push_back(static_cast<uint8_t>((originalLengthBits >> (i * 8)) & 0xff));
    }

    return paddedMessage;
}

std::string toHexString(uint32_t value) {
    std::ostringstream hexStream;
    hexStream << std::hex << std::setw(8) << std::setfill('0') << value;
    return hexStream.str();
}

std::string sha256(const std::string& input) {
    std::vector<uint8_t> message(input.begin(), input.end());
    message = padMessage(message);

    for (size_t i = 0; i < message.size(); i += 64) {
        std::array<uint32_t, 64> w{};

        for (int t = 0; t < 16; ++t) {
            w[t] = (message[i + 4 * t] << 24) |
                (message[i + 4 * t + 1] << 16) |
                (message[i + 4 * t + 2] << 8) |
                (message[i + 4 * t + 3]);
        }

        for (int t = 16; t < 64; ++t) {
            uint32_t s0 = rightRotate(w[t - 15], 7) ^ rightRotate(w[t - 15], 18) ^ (w[t - 15] >> 3);
            uint32_t s1 = rightRotate(w[t - 2], 17) ^ rightRotate(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }

        std::array<uint32_t, 8> workingVars = h;

        for (int t = 0; t < 64; ++t) {
            uint32_t S1 = rightRotate(workingVars[4], 6) ^ rightRotate(workingVars[4], 11) ^ rightRotate(workingVars[4], 25);
            uint32_t ch = (workingVars[4] & workingVars[5]) ^ (~workingVars[4] & workingVars[6]);
            uint32_t temp1 = workingVars[7] + S1 + ch + k[t] + w[t];
            uint32_t S0 = rightRotate(workingVars[0], 2) ^ rightRotate(workingVars[0], 13) ^ rightRotate(workingVars[0], 22);
            uint32_t maj = (workingVars[0] & workingVars[1]) ^ (workingVars[0] & workingVars[2]) ^ (workingVars[1] & workingVars[2]);
            uint32_t temp2 = S0 + maj;

            workingVars[7] = workingVars[6];
            workingVars[6] = workingVars[5];
            workingVars[5] = workingVars[4];
            workingVars[4] = workingVars[3] + temp1;
            workingVars[3] = workingVars[2];
            workingVars[2] = workingVars[1];
            workingVars[1] = workingVars[0];
            workingVars[0] = temp1 + temp2;
        }

        for (int t = 0; t < 8; ++t) {
            h[t] += workingVars[t];
        }
    }

    std::ostringstream result;
    for (const auto& hashValue : h) {
        result << toHexString(hashValue);
    }

    return result.str();
}

int main() {
    std::string input;
    std::cout << "Enter input string: ";
    std::getline(std::cin, input);

    std::string hash = sha256(input);
    std::cout << "SHA-256 HASH: " << hash << std::endl;

    return 0;
}
