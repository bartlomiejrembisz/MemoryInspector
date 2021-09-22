#include <algorithm>
#include <fstream>
#include <iostream>

#include <array>

#include <regex>

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>

#define PRINTF_PTR  "0x%" PRIxPTR
#define PRINTF_BYTE "%02" PRIx8
#define PRINTF_WORD PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE " " PRINTF_BYTE
#define PRINTF_DWORD PRINTF_WORD "  " PRINTF_WORD

const volatile char * volatile testString = "THIS IS MY STRING";

constexpr size_t SIZE_PAGE = 0x1000;

/*
 *  @brief  Get the memory dump for pid.
 */
template <size_t SIZE = SIZE_PAGE>
std::ostream &PrintMemoryDump(const std::string &processPid, const std::string &permissions, std::ostream &outStream = std::cout);

template <size_t SIZE = SIZE_PAGE>
std::ostream &PrintPage(const uint8_t *pBuffer, uint64_t startAddress = 0, std::ostream &outStream = std::cout);

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
        PrintMemoryDump<SIZE_PAGE>(processPid, permissions);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}

template <size_t SIZE>
std::ostream &PrintMemoryDump(const std::string &processPid, const std::string &permissions, std::ostream &outStream)
{
    //! Multiple of PAGE_SIZE
    static_assert(0 == (SIZE % SIZE_PAGE), "SIZE needs to be PAGE_SIZE aligned");

    const std::regex lineRegex("([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r][-w][-x])");
    const std::string procPath(std::string("/proc/") + processPid);
    const std::string mapFilePath(procPath + "/maps");
    const std::string memFilePath(procPath + "/mem");

    outStream << std::hex;
    outStream << mapFilePath << '\n';
    outStream << memFilePath << '\n';
    
    std::ifstream mapFile(mapFilePath, std::ios::in);
    std::ifstream memFile(memFilePath, std::ios::in);

    if (!mapFile.is_open() || !memFile.is_open())
        return outStream;

    std::array<uint8_t, SIZE> buffer;

    std::string line;
    while (std::getline(mapFile, line))
    {
        std::smatch regexMatches;
        if(std::regex_search(line, regexMatches, lineRegex))
        {
            if (3 < regexMatches.size())
            {
                uint64_t regionTop = std::stoull(regexMatches[1], 0, 16);
                const uint64_t regionEnd = std::stoull(regexMatches[2], 0, 16);
                size_t regionSize = regionEnd - regionTop;
                const std::string regionPermissions(regexMatches[3]);
                
                if (!std::all_of(permissions.begin(), permissions.end(), [&](const char c) { return (regionPermissions.find(c) != std::string::npos); }))
                    continue;
                
                outStream << '\n' << line << '\n';
                auto flags = outStream.flags();
                outStream << "size=" << std::dec << regionSize << " bytes" << ", pages=" << (regionSize / SIZE) << '\n';
                outStream.flags(flags);
                for (; regionTop < regionEnd; regionTop += buffer.size())
                {
                    memFile.seekg(regionTop);
                    memFile.read(reinterpret_cast<char *>(buffer.data()), buffer.size());

                    outStream << "regionTop=0x" << regionTop << '\n';
                    PrintPage<SIZE>(buffer.data(), regionTop, outStream) << '\n';
                }
            }
        }
        else
        {
            outStream << "Regex match failure, line=" << line << '\n';
        }
    }

    // std::stoull()

    return outStream;
}

template <size_t SIZE>
std::ostream &PrintPage(const uint8_t *pBuffer, uint64_t startAddress, std::ostream &outStream)
{
    //! Multiple of PAGE_SIZE
    static_assert(0 == (SIZE % SIZE_PAGE), "SIZE needs to be PAGE_SIZE aligned");

    constexpr size_t nBytesPerLine = 16;
    constexpr size_t nLines = SIZE / nBytesPerLine;
    constexpr size_t outputBufferSize = 84 + 3;

    char outputBuffer[outputBufferSize];

    const uint8_t *pNextLine = pBuffer;

    for (size_t nLine = 0; nLine < nLines; ++nLine, pNextLine += nBytesPerLine)
    {
        if (std::all_of(pNextLine, pNextLine + nBytesPerLine, [](const uint8_t byte){ return 0 == byte; }))
        	continue;

        const size_t lineAddress = startAddress + (nLine * nBytesPerLine);
        size_t nBytesWritten = 0;

        //! Append address.
        nBytesWritten += snprintf(&outputBuffer[nBytesWritten], outputBufferSize - nBytesWritten, PRINTF_PTR ":  ", lineAddress);
        
        for (size_t i = 0; i < nBytesPerLine / 2; ++i)
            nBytesWritten += snprintf(&outputBuffer[nBytesWritten], outputBufferSize - nBytesWritten, PRINTF_BYTE " ",  *(pNextLine + i));

        nBytesWritten += snprintf(&outputBuffer[nBytesWritten], outputBufferSize - nBytesWritten, "  ");

        for (size_t i = 0; i < nBytesPerLine / 2; ++i)
            nBytesWritten += snprintf(&outputBuffer[nBytesWritten], outputBufferSize - nBytesWritten, PRINTF_BYTE " ",  *(pNextLine + i));

        nBytesWritten += snprintf(&outputBuffer[nBytesWritten], outputBufferSize - nBytesWritten, " |");
        
        for (size_t i = 0; i < nBytesPerLine; ++i)
        {
            const char * const pFormat = std::isprint(*(pNextLine + i)) ? "%c" : ".";
            nBytesWritten += snprintf(&outputBuffer[nBytesWritten], outputBufferSize - nBytesWritten, pFormat,  *(pNextLine + i));
        }

        nBytesWritten += snprintf(&outputBuffer[nBytesWritten], outputBufferSize - nBytesWritten, "|");

        outStream << outputBuffer << '\n';
    }


    return outStream;
}
