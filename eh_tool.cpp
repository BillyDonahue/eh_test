
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

bool kVerboseHeaders = false;

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

    bool multiLine = (n >= 16);
    if (multiLine)
        os << "\n    ";
    int col = 0;
    for (; n--; ++cp) {
        os << sep;
        os << std::setw(2) << +*cp;
        sep = " ";
        if (++col == 16) {
            os << "\n    ";
            col = 0;
            sep = "";
        }
    }
    os << std::dec;
    if (multiLine)
        os << "\n";
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
    oss << std::hex << std::showbase << +v;
    return oss.str();
}

class ElfScan {
public:
    struct ProgramHeader {
        size_t fOffset;
        Elf64_Phdr pHeader;
    };

    struct SectionHeader {
        size_t fOffset;
        std::string name;
        Elf64_Shdr sHeader;
    };

    explicit ElfScan(std::string s) : image(std::move(s)) {}

    void scanElfHeader() {
        memcpy(&eHeader, &image[0], sizeof(eHeader));

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

        if (kVerboseHeaders) {
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
    }

    void scanProgramHeaders() {
        size_t pho = eHeader.e_phoff;
        pHeaders.reserve(eHeader.e_phnum);
        for (size_t phi = 0; phi < eHeader.e_phnum; ++phi, pho += eHeader.e_phentsize) {
            Elf64_Phdr pHeader;
            if (image.size() <= sizeof(pHeader)) {
                std::cerr << "ELF image (" << image.size() << ") not big enough for pHeader ("
                    << sizeof(pHeader) << ")" << std::endl;
                throw std::runtime_error("ELF too small");
            }
            memcpy(&pHeader, image.data() + pho, sizeof(pHeader));

            if (kVerboseHeaders) {
                std::cout << "Program segment header [" << phi << "], offset:" << hexInt(pho) << ": {\n";
                auto hdrDump = [](const char* field, auto x) -> std::ostream& {
                    return std::cout << "  ." << field << ": " << hexInt(x) << "\n";
                };
#define HDRF_(f) hdrDump(#f, pHeader.f)
                HDRF_(p_type);         /* Segment type */
                HDRF_(p_flags);        /* Segment flags */
                HDRF_(p_offset);       /* Segment file offset */
                HDRF_(p_vaddr);        /* Segment virtual address */
                HDRF_(p_paddr);        /* Segment physical address */
                HDRF_(p_filesz);       /* Segment size in file */
                HDRF_(p_memsz);        /* Segment size in memory */
                HDRF_(p_align);        /* Segment alignment */
#undef HDRF_
                struct {
                    Elf64_Word t;
                    std::string name;
                } static const pTypes[] = {
#define TTE_(s) {s, #s}
                    TTE_(PT_NULL),
                    TTE_(PT_LOAD),
                    TTE_(PT_DYNAMIC),
                    TTE_(PT_INTERP),
                    TTE_(PT_NOTE),
                    TTE_(PT_SHLIB),
                    TTE_(PT_PHDR),
                    TTE_(PT_TLS),
                    TTE_(PT_NUM),
                    TTE_(PT_LOOS),
                    TTE_(PT_GNU_EH_FRAME),
                    TTE_(PT_GNU_STACK),
                    TTE_(PT_GNU_RELRO),
                    TTE_(PT_LOSUNW),
                    TTE_(PT_SUNWBSS),
                    TTE_(PT_SUNWSTACK),
                    TTE_(PT_HISUNW),
                    TTE_(PT_HIOS),
                    TTE_(PT_LOPROC),
                    TTE_(PT_HIPROC),
#undef TTE_
                };
                for (auto&& pt : pTypes) {
                    if (pHeader.p_type == pt.t) {
                        std::cout << "     [type: " << pt.name << "]\n";
                    }
                }
                std::cout << "}\n";
            }
            pHeaders.push_back({pho, pHeader});
        }
    }

    void scanSectionHeaders() {
        size_t sho = eHeader.e_shoff;
        sHeaders.reserve(eHeader.e_shnum);
        for (size_t shi = 0; shi < eHeader.e_shnum; ++shi, sho += eHeader.e_shentsize) {
            Elf64_Shdr sHeader;
            if (image.size() <= sizeof(sHeader)) {
                std::cerr << "ELF image (" << image.size() << ") not big enough for sHeader ("
                    << sizeof(sHeader) << ")" << std::endl;
                throw std::runtime_error("ELF too small");
            }
            memcpy(&sHeader, image.data() + sho, sizeof(sHeader));
            sHeaders.push_back({sho, {}, sHeader});
        }

        // Now go back and give them all names, now that we have seen the string table section.
        const auto& strTabSec = sHeaders[eHeader.e_shstrndx].sHeader;
        const char* strTab = &image[strTabSec.sh_offset];
        for (auto&& s : sHeaders) {
            s.name = std::string(strTab + s.sHeader.sh_name);
        }

        if (kVerboseHeaders) {
            for (size_t shi = 0; shi != sHeaders.size(); ++shi) {
                const auto& s = sHeaders[shi];
                std::cout << "Section header [" << shi << "]"
                    ", name: \"" << s.name << "\""
                    ", offset:" << hexInt(s.fOffset) << ": {\n";
                auto hdrDump = [](const char* field, auto x) -> std::ostream& {
                    return std::cout << "  ." << field << ": " << hexInt(x) << "\n";
                };
#define HDRF_(f) hdrDump(#f, s.sHeader.f)
                HDRF_(sh_name);                /* Section name (string tbl index) */
                HDRF_(sh_type);                /* Section type */
                HDRF_(sh_flags);               /* Section flags */
                HDRF_(sh_addr);                /* Section virtual addr at execution */
                HDRF_(sh_offset);              /* Section file offset */
                HDRF_(sh_size);                /* Section size in bytes */
                HDRF_(sh_link);                /* Link to another section */
                HDRF_(sh_info);                /* Additional section information */
                HDRF_(sh_addralign);           /* Section alignment */
                HDRF_(sh_entsize);             /* Entry size if section holds table */
#undef HDRF_
                std::cout << "}\n";
            }
        }
    }

    void load() {
        scanElfHeader();
        std::cout << std::endl;
        scanProgramHeaders();
        std::cout << std::endl;
        scanSectionHeaders();
    }

    const SectionHeader* findSection(const std::string& name) const {
        for (auto&& s : sHeaders)
            if (s.name == name)
                return &s;
        return nullptr;
    }

    void dumpEhFrame() {
        auto secHeader = findSection(kSectionEhFrame);
        if (!secHeader)
            throw std::runtime_error("missing .eh_frame section");
        size_t secSize = secHeader->sHeader.sh_size;
        std::cout << "\"" << secHeader->name << "\"" << std::endl;
        const char* sectionData = &image[secHeader->sHeader.sh_offset];
        std::cout << "=====" << std::endl;

        hexDump(std::cout, ".eh_frame section", sectionData, std::min(secSize, size_t{1} << 10)) << "\n";

        // 1 or more CIE, read while `pos < secSize`.
        size_t pos = 0;

        // CFI:
        //   Common Information Entry Record
        //   Frame Description Entry Record(s)
        struct Cie {
            size_t length;
            // [4] Length    Required
            // [?8] Extended Length    Optional (if length==0xffffffff)
            uint32_t cieId; // [4] CIE ID    Required
            uint8_t version;
            std::string augmentationString;

            bool hasEhData;
            uint64_t ehData;  // EH Data Optional (present if "eh" appears in augmentationString)

            uint64_t codeAlign;  // Code Alignment Factor    Required LEB128
            uint64_t dataAlign;  // Data Alignment Factor    Required LEB128
            uint64_t returnRegister;  // Return Address Register    Required

            // Augmentation Data Length    Optional
            // Augmentation Data    Optional

            // Initial Instructions    Required
        };

        while (pos < secSize) {
            Cie cie{};

            std::cout << "CFI record:\n";

            {
                uint32_t val;
                memcpy(&val, sectionData + pos, sizeof(val));
                pos += sizeof(val);
                cie.length = val;
            }

            if (cie.length == 0) {
                std::cout << "CIE length==0 terminator";
            }

            if (cie.length == 0xffff'ffff) {
                uint64_t val;
                memcpy(&val, sectionData + pos, sizeof(val));
                pos += sizeof(val);
                cie.length = val;
            }

            std::cout << "  .length: " << hexInt(cie.length) << "\n";

            const char* cieBegin = sectionData + pos;
            const char* cieEnd = cieBegin + cie.length;
            pos += cie.length;
            const char* ciePtr = cieBegin;

            hexDump(std::cout, "  .data", cieBegin, cieEnd - cieBegin) << "\n";

            {
                uint32_t val;
                memcpy(&val, ciePtr, sizeof(val));
                ciePtr += sizeof(val);
                cie.cieId = val;
            }

            if (cie.cieId != 0) {
                std::cout << "  [skip non-CIE record with id " << hexInt(cie.cieId) << "]\n";
                continue;
            }

            {
                uint8_t val;
                memcpy(&val, ciePtr, sizeof(val));
                ciePtr += sizeof(val);
                cie.version = val;
            }

            for (; *ciePtr; ++ciePtr)
                cie.augmentationString.push_back(*ciePtr);

            if (cie.hasEhData = (cie.augmentationString.find("eh") != std::string::npos)) {
                uint64_t val;
                memcpy(&val, ciePtr, sizeof(val));
                ciePtr += sizeof(val);
                cie.ehData = val;
            }

            std::cout << "  .version: " << hexInt(cie.version) << "\n";
            std::cout << "  .augmentationString: \"" << cie.augmentationString << "\"\n";
            if (cie.hasEhData) {
                std::cout << "  .ehData: \"" << hexInt(cie.ehData) << "\"\n";
            }
        }
    }

private:
    std::string image;
    Elf64_Ehdr eHeader;
    std::vector<ProgramHeader> pHeaders;
    std::vector<SectionHeader> sHeaders;
};

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i)
        args.push_back(argv[i]);
    if (args.size() < 1) {
        std::cerr << "need filename" << std::endl;
        return 1;
    }

    std::cout << "ELF file: " << args[1] << "\n";
    std::string elfData = slurp(args[1]);
    std::cout << "size: " << elfData.size() << " (" << std::hex << std::showbase
        << elfData.size() << std::noshowbase << std::dec << ")\n";

    ElfScan elfScan(std::move(elfData));
    elfScan.load();

    elfScan.dumpEhFrame();

    return 0;
}
