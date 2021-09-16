#include <algorithm>
#include <fstream>
#include <iostream>

#include <regex>

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>

#define PRINTF_PTR  "0x%" PRIxPTR
#define PRINTF_BYTE "%02" PRIx8
#define PRINTF_WORD PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE
#define PRINTF_DWORD PRINTF_WORD "  " PRINTF_WORD

const volatile char * volatile testString = "THIS IS MY STRING";

/*
 *  @brief  Get the memory dump for pid.
 */
std::string GetMemoryDump(const std::string &processPid, const std::string &permissions);

std::string ConvertBufferToHexdump(const uint8_t *pBuffer, const size_t size, uint64_t startAddress = 0);

int main(int argc, char** argv)
{
    if ((argc < 2) || (argc > 3))
    {
        std::cout << argc << '\n';
        std::cout << " Memory inspector.\n"
                << "    Usage: " << argv[0] << " <pid> <permissions[rwx]>\n";
        
        return 1;
    }

    std::string processPid(argv[1]);
    std::string permissions(argv[2]);
    if(!std::all_of(permissions.begin(), permissions.end(), [](const char c) { return ('r' == c) || ('w' == c) || ('x' == c); }))
    {
        std::cerr << "Invalid permissions, expected at least one of [rwx]\n";
        
        return 1;
    }

    if ((0 != getuid()) && ("self" != processPid))
    {
        std::cerr << "Memory inspector requires root permissions.\n";

        return 1;
    }
    
    try
    {
        std::cout << GetMemoryDump(processPid, permissions) << '\n';
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}

std::string GetMemoryDump(const std::string &processPid, const std::string &permissions)
{
    const std::regex lineRegex("([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r][-w][-x])");
    const std::string procPath(std::string("/proc/") + processPid);
    const std::string mapFilePath(procPath + "/maps");
    const std::string memFilePath(procPath + "/mem");

    std::string output;

    output += mapFilePath + '\n';
    output += memFilePath + '\n';
    
    std::ifstream mapFile(mapFilePath, std::ios::in);
    std::ifstream memFile(memFilePath, std::ios::in);

    if (!mapFile.is_open() || !memFile.is_open())
        return output;

    std::vector<uint8_t> buffer;
    buffer.resize(4096);

    std::string line;
    while (std::getline(mapFile, line))
    {
        std::smatch regexMatches;
        if(std::regex_search(line, regexMatches, lineRegex))
        {
            if (3 < regexMatches.size())
            {
                const uint64_t regionStart = std::stoull(regexMatches[1], 0, 16);
                const uint64_t regionEnd = std::stoull(regexMatches[2], 0, 16);
                const size_t regionSize = regionEnd - regionStart;
                const std::string regionPermissions(regexMatches[3]);

                if (!std::all_of(permissions.begin(), permissions.end(), [&](const char c) { return (regionPermissions.find(c) != std::string::npos); }))
                    continue;

                buffer.resize(regionSize);

                memFile.seekg(regionStart);
                memFile.read(reinterpret_cast<char *>(buffer.data()), regionSize);

                // std::cout << std::hex << regionStart << " " << regionEnd << " " << regionPermissions << " " << regionSize << '\n';
                output.append(line + '\n');
                output.append(ConvertBufferToHexdump(buffer.data(), buffer.size(), regionStart) + '\n');
            }
        }
        else
        {
            std::cout << "Regex match failure, line=" << line << '\n';
        }
    }

    // std::stoull()

    return output;
}

std::string ConvertBufferToHexdump(const uint8_t *pBuffer, const size_t bufferSize, uint64_t startAddress)
{
    //! pointer + colon + (16 02 bytes + space) + 4 extra spaces + 18 for ascii
    std::vector<char> output;
    output.resize((bufferSize / 16) * (16 + 1 + (16 * 3) + 4 + 18) + 1);

    size_t nBytesWritten = 0;
    const size_t outputBufferSize = output.size();

    for (size_t nBytesDumped = 0; nBytesDumped < bufferSize;)
    {
        const size_t nBytesLeft = bufferSize - nBytesDumped;
        const size_t nBytesToDump = (nBytesLeft > 16) ? 16 : nBytesLeft;
        const uint8_t *pData = pBuffer + nBytesDumped;

        if (std::all_of(pData, pData + nBytesToDump, [](const uint8_t byte){ return 0 == byte; }))
        {
            nBytesDumped += nBytesToDump;
            continue;
        }

        //! Append address.
        nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, PRINTF_PTR ":  ", (startAddress + nBytesDumped));
        
        for (size_t i = 0; i < nBytesToDump; ++i)
            nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, PRINTF_BYTE " ",  *(pData + i));

        nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, " |");
        for (size_t i = 0; i < nBytesToDump; ++i)
        {
            const char *pFormat = std::isprint(*(pData + i)) ? "%c" : ".";
            nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, pFormat,  *(pData + i));
            
            // if (std::isprint(*(pData + i)))
            //     nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, "%c",  *(pData + i));
            // else
            //     nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, ".");
        }
        nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, "|\n");

        // nBytesWritten += snprintf(output.data() + nBytesWritten, outputBufferSize - nBytesWritten, PRINTF_DWORD,  pBuffer + nBytesDumped);

        nBytesDumped += nBytesToDump;
    }

    return std::string(output.begin(), output.begin() + nBytesWritten);
}
