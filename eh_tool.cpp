
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include <cassert>

#include <elf.h>

namespace {

const std::string kElfMagic = std::string(ELFMAG, SELFMAG);
const std::string kSectionEhFrame = ".eh_frame";

std::string slurp(const std::string& fileName) {
    std::ifstream ifs(fileName, std::ios::binary);
    std::vector<uint8_t> data;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

std::ostream& hexDump(std::ostream& os, const std::string& label, const void* p, size_t n) {
    auto cp = reinterpret_cast<const uint8_t*>(p);
    os << std::hex << std::setfill('0');
    const char* sep = "";
    if (label.size())
        os << label << ": ";
    os << "[";
    for (; n--; ++cp) {
        os << sep;
        os << std::setw(2) << +*cp;
        sep = " ";
    }
    os << std::dec;
    os << "]";
    return os;
}

std::string hexString(const void* p, size_t n) {
    std::ostringstream oss;
    hexDump(oss, {}, p, n);
    return oss.str();
}

std::string hexString(const std::string& s) {
    return hexString(s.data(), s.size());
}

template <typename T>
std::string hexInt(T v) {
    std::ostringstream oss;
    oss << std::hex << std::showbase << v;
    return oss.str();
}

void analyzeElf(const std::string& image) {
    size_t pos = 0;

    Elf64_Ehdr eHeader;
    memcpy(&eHeader, &image[pos], sizeof(eHeader));
    pos += sizeof(eHeader);

    const unsigned char* ident = eHeader.e_ident;
    std::string magic((const char*)ident, (size_t)SELFMAG);
    if (magic != kElfMagic) {
        std::cerr << "Expected " << hexString(kElfMagic) << ", got " << hexString(magic) << ".\n";
        assert(0);
    }

    auto eClass = static_cast<uint8_t>(ident[EI_CLASS]);

    if (eClass != ELFCLASS64) {
        std::cerr << "Expected " << ELFCLASS64 << ", got " << eClass << ".\n";
        assert(0);
    }
    std::cout << "  .e_ident: {\n";
    hexDump(std::cout, "    ei_magic", &ident[0], SELFMAG) << "\n";
    hexDump(std::cout, "    ei_class", &ident[EI_CLASS], 1) << "\n";
    hexDump(std::cout, "    ei_data", &ident[EI_DATA], 1) << "\n";
    hexDump(std::cout, "    ei_version", &ident[EI_VERSION], 1) << "\n";
    hexDump(std::cout, "    ei_osabi", &ident[EI_OSABI], 1) << "\n";
    hexDump(std::cout, "    ei_abiversion", &ident[EI_ABIVERSION], 1) << "\n";
    std::cout << "  }\n";

    auto hdrDump = [](const char* field, auto x) {
        std::cout << "  ." << field << ": " << hexInt(x) << "\n";
    };
#define HDRF_(f) hdrDump(#f, eHeader.f);
    HDRF_(e_type)             /* Object file type */
    HDRF_(e_machine)          /* Architecture */
    HDRF_(e_version)          /* Object file version */
    HDRF_(e_entry)            /* Entry point virtual address */
    HDRF_(e_phoff)            /* Program header table file offset */
    HDRF_(e_shoff)            /* Section header table file offset */
    HDRF_(e_flags)            /* Processor-specific flags */
    HDRF_(e_ehsize)           /* ELF header size in bytes */
    HDRF_(e_phentsize)        /* Program header table entry size */
    HDRF_(e_phnum)            /* Program header table entry count */
    HDRF_(e_shentsize)        /* Section header table entry size */
    HDRF_(e_shnum)            /* Section header table entry count */
    HDRF_(e_shstrndx)         /* Section header string table index */
#undef HDRF_
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i)
        args.push_back(argv[i]);
    //for (auto&& a : args)
    //    std::cerr << "arg: `" << a << "`\n";
    if (args.size() < 1) {
        std::cerr << "need filename\n";
        return 1;
    }

    std::cout << "ELF file: " << args[1] << "\n";
    std::string elfData = slurp(args[1]);
    std::cout << "size: " << elfData.size() << " (" << std::hex << std::showbase
        << elfData.size() << std::noshowbase << std::dec << ")\n";
    analyzeElf(elfData);
    return 0;
}
