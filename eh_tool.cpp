
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <cassert>

#include <elf.h>
#include <libdwarf/dwarf.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

namespace {

using namespace fmt::literals;

// gcc extension: 
// https://code.woboq.org/llvm/compiler-rt/lib/builtins/gcc_personality_v0.c.html#_M/DW_EH_PE_indirect
// https://git.savannah.nongnu.org/cgit/libunwind.git/tree/include/dwarf.h

#define DW_EH_PE_FORMAT_MASK    0x0f    /* format of the encoded value */
#define DW_EH_PE_APPL_MASK      0x70    /* how the value is to be applied */
/* Flag bit.  If set, the resulting pointer is the address of the word
 * that contains the final address.  */
#define DW_EH_PE_indirect       0x80


const std::string kElfMagic = std::string(ELFMAG, SELFMAG);
const std::string kSectionEhFrame = ".eh_frame";
const std::string kSectionText = ".text";
const std::string kSectionGccExceptTable= ".gcc_except_table";

bool verboseElfDecode = true;
bool verboseDwarfDecode = true;

std::string slurp(const std::string& fileName) {
    std::ifstream ifs(fileName, std::ios::binary);
    std::vector<uint8_t> data;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

std::ostream& hexDump(std::ostream& os, const std::string& label, const void* p, size_t n) {
    auto cp = reinterpret_cast<const uint8_t*>(p);
    bool multiLine = (n >= 16);
    if (label.size())
        fmt::print(os, "{}: ", label);
    fmt::print(os, "[");
    const char* kLineSep = "\n    ";
    if (multiLine)
        fmt::print(os, kLineSep);
    const char* sep = "";
    int col = 0;
    for (; n--; ++cp) {
        fmt::print(os, "{}{:#04x}", sep, +*cp);
        sep = " ";
        if (++col == 16) {
            fmt::print(os, kLineSep);
            col = 0;
            sep = "";
        }
    }
    if (multiLine)
        fmt::print(os, "\n  ");
    fmt::print(os, "]");
    return os;
}

std::string hexString(const void* p, size_t n) {
    std::ostringstream oss;
    hexDump(oss, {}, p, n);
    return oss.str();
}

std::string hexString(std::string_view s) {
    return hexString(s.data(), s.size());
}

template <typename T>
std::string hexInt(T v) {
    std::ostringstream oss;
    oss << std::hex << std::showbase << +v;
    return oss.str();
}

std::string encStr(uint8_t encoding) {
    std::vector<std::string> parts;
    if (encoding == DW_EH_PE_omit)
        return "DW_EH_PE_omit";

    auto part = [&](auto&& s) { parts.push_back(s); };

#define P_(x) case x: part(#x); break;
    // lower nybble: value format
    switch (encoding & DW_EH_PE_FORMAT_MASK) {
        P_(DW_EH_PE_absptr)
        P_(DW_EH_PE_uleb128)
        P_(DW_EH_PE_udata2)
        P_(DW_EH_PE_udata4)
        P_(DW_EH_PE_udata8)
        P_(DW_EH_PE_sleb128)
        P_(DW_EH_PE_sdata2)
        P_(DW_EH_PE_sdata4)
        P_(DW_EH_PE_sdata8)
        default: part("[lower:?]"); break;
    }
    // upper nybble: application
    switch (encoding & DW_EH_PE_APPL_MASK) {
        P_(DW_EH_PE_pcrel)
        P_(DW_EH_PE_textrel)
        P_(DW_EH_PE_datarel)
        P_(DW_EH_PE_funcrel)
        P_(DW_EH_PE_aligned)
        P_(0)
        default: part("[upper:?]"); break;
    }
    if (encoding & DW_EH_PE_indirect)
        part("DW_EH_PE_indirect");
#undef P_

    std::string result = hexInt(encoding) + ": [";
    const char* sep = "";
    for (auto&& p : parts) {
        result += sep;
        result += p;
        sep = " | ";
    }
    result += "]";
    return result;
}

uint64_t decodeULEB128(std::string_view& data) {
    const char* in = data.data();
    uint64_t val = 0;
    int shift = 0;
    uint64_t c;
    do {
        c = static_cast<unsigned char>(*in++);
        // std::cout << "peek: " << hexInt(c) << "\n";
        val |= (c & 0x7f) << shift;
        if (!(c & 0x80))
            break;
        shift += 7;
    } while (c & 0x80);
    data.remove_prefix(in - data.data());
    return val;
}

int64_t decodeSLEB128(std::string_view& data) {
    const char* in = data.data();
    int64_t val = 0;
    int64_t shift = 0;
    int64_t c;
    do {
        c = *in++;
        val |= (c & 0x7f) << shift;
        shift += 7;
    } while (c & 0x80);
    if (c & 0x40)
        val |= static_cast<int64_t>((~uint64_t{0}) << shift);
    data.remove_prefix(in - data.data());
    return val;
}

template <typename T>
T readInteger(std::string_view& data) {
    T t;
    std::copy_n(data.begin(), sizeof(t), reinterpret_cast<char*>(&t));
    data.remove_prefix(sizeof(t));
    return t;
}


uint64_t decodeDwarfGenericInner(uint8_t encoding,
                                 std::string_view elfImage,
                                 uint64_t secAddr,
                                 std::string_view secImage,
                                 std::string_view& data /* inout */) {
    std::string_view save = data;
    uint64_t r = 0;
    // Low nybble determines numeric encoding
    switch (encoding & DW_EH_PE_FORMAT_MASK) {
        case DW_EH_PE_uleb128:
            r = decodeULEB128(data);
            break;
        case DW_EH_PE_udata2:
            r = readInteger<uint16_t>(data);
            break;
        case DW_EH_PE_udata4:
            r = readInteger<uint32_t>(data);
            break;
        case DW_EH_PE_udata8:
        case DW_EH_PE_absptr:
            r = readInteger<uint64_t>(data);
            break;
        case DW_EH_PE_sleb128:
            r = static_cast<uint64_t>(decodeSLEB128(data));
            break;
        case DW_EH_PE_sdata2:
            r = static_cast<uint64_t>(readInteger<int16_t>(data));
            break;
        case DW_EH_PE_sdata4:
            r = static_cast<uint64_t>(readInteger<int32_t>(data));
            break;
        case DW_EH_PE_sdata8:
            r = static_cast<uint64_t>(readInteger<int64_t>(data));
            break;
    }

    // High nybble specifies contextual adjustments applied to the numeric value:
    switch (encoding & DW_EH_PE_APPL_MASK) {
        case DW_EH_PE_pcrel:
            auto raw = r;
            uint64_t secOffset = save.data() - secImage.data();
            r = secAddr + secOffset + raw;
            std::cout << fmt::format(
                    "   [pcrel: secAddr:{:#x} + secOffset:{:#x} + raw:{:#x} = {:#x}]\n",
                    secAddr, secOffset, raw, r);
            break;
    }

    return r;
}

uint64_t decodeDwarfGeneric(uint8_t encoding, std::string_view elfImage, uint64_t secAddr,
                            std::string_view secImage, std::string_view& data /* inout */) {
    std::string_view save = data;
    uint64_t pos = save.data() - elfImage.data();
    auto r = decodeDwarfGenericInner(encoding, elfImage, secAddr, secImage, data);
    if (verboseDwarfDecode) {
        std::string_view consumed(save.data(), data.data() - save.data());
        fmt::print("   [decodeDwarf: pos: {:#x}, raw: {}, enc: {}]\n",
                   pos, hexString(consumed), encStr(encoding));
    }
    return r;
}

struct Elf {
    struct ProgramHeader {
        size_t hdrAt;
        Elf64_Phdr pHeader;
    };

    struct SectionHeader {
        size_t hdrAt;
        std::string name;
        Elf64_Shdr sHeader;
    };

    const SectionHeader* findSection(std::string_view name) const {
        for (auto&& s : sHeaders)
            if (s.name == name)
                return &s;
        return nullptr;
    }

    uint8_t readByte(std::string_view& data) const {
        uint8_t r = data.at(0);
        data.remove_prefix(1);
        fmt::print("   [readByte at {:#10x}: {:#04x}]\n", data.data() - image.data(), +r);
        return r;
    }


    std::string ptrDebug(uint64_t vma) const {
        // search all section headers to see which contain this vma.
        for (auto&& sec : sHeaders) {
            auto&& sh = sec.sHeader;
            if (vma >= sh.sh_addr && vma < sh.sh_addr + sh.sh_size) {
                return fmt::format("[{:#x} = <{} + {:#x}>]", vma, sec.name, vma - sh.sh_addr);
            }
        }
        return fmt::format("[{:#x}]", vma);
    }

    std::string_view image;
    Elf64_Ehdr eHeader;
    std::vector<ProgramHeader> pHeaders;
    std::vector<SectionHeader> sHeaders;
};


// CFI:
//   - Common Information Entry Record
//   - Frame Description Entry Record(s)

struct Cie {
    bool hasEhData() const { return augmentationString.find("eh") != std::string::npos; }
    bool hasAugmentation() const { return augmentationString.find('z') == 0; }

    size_t pos;  // starting offset within section
    uint32_t cieId; // [4] CIE ID == 0 (same position as the nonzero Fde ciePointer)
    uint8_t version;
    std::string augmentationString;
    uint64_t ehData;  // EH Data Optional (present if "eh" appears in augmentationString)
    uint64_t codeAlign;  // Code Alignment Factor Required ULEB128
    int64_t dataAlign;   // Data Alignment Factor Required SLEB128
    uint8_t returnRegister;  // Return Address Register ?   Required
    std::string instructions;  // initial call frame dwarf instructions
    uint8_t lsdaEnc = DW_EH_PE_omit; // encoding for LSDA pointers in the FDEs
    uint8_t personalityEnc;  // Personality function's encoding.
    uint8_t addressEnc;  // encoding for addresses in the FDEs
    uint64_t personality;
};

struct Fde {
    size_t pos;  // starting offset within section
    uint64_t length; // [4] Length    Required
                     // [?8] Extended Length    present iff length == 0xffffffff
    uint32_t ciePointer;

    uint64_t pcBegin;
    uint64_t pcRange;
    std::string augmentationData;
    uint64_t lsdaAddr = 0;
    std::string instructions;
};

struct Lsda {
    uint64_t addr;
    bool hasLpBase;
    uint64_t lpBase;
    uint64_t ttStart;
    uint8_t csEnc;
    uint64_t csSize;
    uint64_t actionStart;
};

class LsdaScan {
public:
    LsdaScan(const Elf* elf) : elf(elf) {
        sec = elf->findSection(".gcc_except_table");
    }

    /**
        A 1 byte encoding of the following field (a DW_EH_PE_xxx value).

        If the encoding is not DW_EH_PE_omit, the landing pad base. This is the
        base from which landing pad offsets are computed. If this is omitted, the
        base comes from calling _Unwind_GetRegionStart, which returns the beginning
        of the code described by the current FDE. In practice this field is
        normally omitted.

        A 1 byte encoding of the entries in the type table (a DW_EH_PE_xxx value).

        If the encoding is not DW_EH_PE_omit, the types table pointer. This is an
        unsigned LEB128 value, and is the byte offset from this field to the start
        of the types table used for exception matching.

        A 1 byte encoding of the fields in the call-site table (a DW_EH_PE_xxx value).

        An unsigned LEB128 value holding the length in bytes of the call-site table.
     */
    Lsda scan(uint64_t addr) {
        Lsda lsda{};
        fmt::print("[LSDA] at {}\n", elf->ptrDebug(addr));
        lsda.addr = addr;
        std::string_view data = elf->image.substr(addr);
        uint8_t lpBaseEnc = elf->readByte(data);
        fmt::print("    .landingPadBaseEncoding: {}\n", encStr(lpBaseEnc));
        if (lpBaseEnc != DW_EH_PE_omit) {
            lsda.hasLpBase = true;
            lsda.lpBase = decodeDwarf(lpBaseEnc, data);
            fmt::print("    .lpBase: {}\n", encStr(lsda.lpBase));
        }
        uint8_t ttEnc = elf->readByte(data);
        if (ttEnc != DW_EH_PE_omit) {
            fmt::print("    .ttEnc: {}\n", encStr(ttEnc));
            lsda.ttStart = decodeDwarf(DW_EH_PE_uleb128 | DW_EH_PE_pcrel, data);
        } else {
            lsda.ttStart = 0;
        }
        fmt::print("    .ttStart: {}\n", elf->ptrDebug(lsda.ttStart));

        lsda.csEnc = elf->readByte(data);
        fmt::print("    .csEnc: {}\n", encStr(lsda.csEnc));
        lsda.csSize = decodeDwarf(DW_EH_PE_uleb128, data);
        fmt::print("    .csSize: {:#x}\n", lsda.csSize);
        lsda.actionStart = sec->sHeader.sh_addr + (data.data() - secData().data()) + lsda.csSize;
        fmt::print("    .actionStart: {}\n", elf->ptrDebug(lsda.actionStart));
        return lsda;
    }

    uint64_t decodeDwarf(uint8_t enc, std::string_view& data) const {
        return decodeDwarfGeneric(enc, elf->image, sec->sHeader.sh_addr, secData(), data);
    }

    std::string_view secData() const {
        return elf->image.substr(sec->sHeader.sh_offset, sec->sHeader.sh_size);
    }

    const Elf* elf;
    const Elf::SectionHeader* sec;
};

struct Cfi {
public:
    Cfi(const Elf* elf, const Elf::SectionHeader* sec) : elf(elf), sec(sec) {}

    void scan();

    uint64_t decodeDwarf(uint8_t encoding, std::string_view& data);

    const Cie* cieLookup(uint64_t ciePos) {
        auto iter = std::find_if(cieVec.begin(), cieVec.end(), [&](const Cie& e) {
            return e.pos == ciePos;
        });
        if (iter == cieVec.end())
            return nullptr;
        return &*iter;
    }

private:
    bool scanCie(std::string_view data, uint32_t startPosition);
    bool scanFde(std::string_view data, uint32_t startPosition, uint32_t cieId);

    std::string_view elfImage() const {
        return elf->image;
    }

    std::string_view secData() const {
        return elfImage().substr(sec->sHeader.sh_offset, sec->sHeader.sh_size);
    }

    uint64_t decodeDwarfInner(uint8_t encoding, std::string_view& data);

public:
    const Elf* elf;
    const Elf::SectionHeader* sec;
    std::vector<Cie> cieVec;
    std::vector<Fde> fdeVec;
};


uint64_t Cfi::decodeDwarf(uint8_t encoding, std::string_view& data) {
    return decodeDwarfGeneric(
            encoding,
            elf->image,
            sec->sHeader.sh_addr,
            elf->image.substr(sec->sHeader.sh_offset, sec->sHeader.sh_size),
            data);
}

bool Cfi::scanCie(std::string_view data, uint32_t startPosition) {
    fmt::print("[CIE]\n");
    Cie cie{};
    cie.pos = startPosition;
    cie.version = elf->readByte(data);
    fmt::print("  .version: {:#4x}\n", cie.version);
    while (!data.empty()) {
        char c = data.front();
        data.remove_prefix(1);
        if (!c)
            break;
        cie.augmentationString.push_back(c);
    }
    fmt::print("  .augmentationString: \"{}\"\n", cie.augmentationString);
    if (cie.hasEhData()) {
        cie.ehData = decodeDwarf(DW_EH_PE_udata4, data);
        fmt::print("  .ehData: {:#10x}\n", cie.ehData);
    }
    cie.codeAlign = decodeDwarf(DW_EH_PE_uleb128, data);
    fmt::print("  .codeAlign: {}\n", cie.codeAlign);
    cie.dataAlign = decodeDwarf(DW_EH_PE_sleb128, data);
    fmt::print("  .dataAlign: {}\n", cie.dataAlign);
    cie.returnRegister = elf->readByte(data);
    fmt::print("  .returnRegister: {}\n", cie.returnRegister);
    if (cie.hasAugmentation()) {
        uint64_t len = decodeDwarf(DW_EH_PE_uleb128, data);
        std::string_view aug = data.substr(0, len);
        data.remove_prefix(len);
        // Contents' meaning determined by augmentationString
        hexDump(std::cout, "  .augmentationData", aug.data(), aug.size()) << "\n";
        // Parse augmentationString, assigning meaning to the augmentationData.
        for (size_t strPos = 1; strPos != cie.augmentationString.size(); ++strPos) {
            switch (cie.augmentationString[strPos]) {
                case 'L':
                    cie.lsdaEnc = elf->readByte(aug);
                    fmt::print("    .lsdaEnc: {}\n", encStr(cie.lsdaEnc));
                    break;
                case 'P':
                    // Encodes encoding spec for a pointer, then the pointer.
                    cie.personalityEnc = elf->readByte(aug);
                    fmt::print("    .personalityEnc: {}\n", encStr(cie.personalityEnc));
                    cie.personality = decodeDwarf(cie.personalityEnc, aug);
                    fmt::print("    .personality: {:1}{}\n",
                               (cie.personalityEnc & DW_EH_PE_indirect) ? "*" : "", elf->ptrDebug(cie.personality));
                    if (cie.personalityEnc & DW_EH_PE_indirect) {
                        auto persLoc = elfImage().substr(cie.personality, 8);
                        uint64_t pers = decodeDwarf(DW_EH_PE_udata8, persLoc);
                        fmt::print("        [* {} = {}]\n", elf->ptrDebug(cie.personality), elf->ptrDebug(pers));
                    }

                    break;
                case 'R':
                    cie.addressEnc = elf->readByte(aug);
                    fmt::print("    .addressEnc: {}\n", encStr(cie.addressEnc));
                    break;
            }
        }
    }
    cie.instructions = data;
    fmt::print("  .instructions: {}\n", hexString(cie.instructions));
    cieVec.push_back(std::move(cie));
    return true;
}

bool Cfi::scanFde(std::string_view data, uint32_t startPosition, uint32_t cieId) {
    Fde fde{};
    fde.pos = startPosition;

    fde.pos = data.data() - secData().data();
    fde.ciePointer = data.data() - secData().data() - cieId - sizeof(cieId);
    fmt::print("[FDE] .ciePointer: {:#04x}\n", fde.ciePointer);

    const Cie* associatedCie = cieLookup(fde.ciePointer);
    if (!associatedCie) {
        throw std::runtime_error(
                fmt::format("No associated CIE {:#x} for FDE {:#x}", fde.ciePointer, fde.pos));
    }

    fde.pcBegin = decodeDwarf(associatedCie->addressEnc, data);
    fmt::print("   .pcBegin: {:#x}\n", fde.pcBegin);
    // pcRange is same format as pcBegin, ignores the apply rule. (libunwind:src/dwarf/Gfde.c)
    fde.pcRange = decodeDwarf(associatedCie->addressEnc & DW_EH_PE_FORMAT_MASK, data);
    fmt::print("   .pcRange: {:#x}, [ range: {} .. {} ]\n",
               fde.pcRange,
               elf->ptrDebug(fde.pcBegin),
               elf->ptrDebug(fde.pcBegin + fde.pcRange));

    if (associatedCie->hasAugmentation()) {
        uint64_t n = decodeDwarf(DW_EH_PE_uleb128, data);
        fde.augmentationData = data.substr(0, n);
        // data.remove_prefix(n);
        fmt::print("   .augmentationData[{}]: {}\n", n, hexString(fde.augmentationData));

        if (associatedCie->lsdaEnc != DW_EH_PE_omit) {
            fde.lsdaAddr = decodeDwarf(associatedCie->lsdaEnc, data);
            fmt::print("   .lsda: {}\n", elf->ptrDebug(fde.lsdaAddr));

            LsdaScan lsdaScan{elf};
            Lsda lsda = lsdaScan.scan(fde.lsdaAddr);
        }
    }
    fde.instructions = data;
    fmt::print("   .instructions: {}\n", hexString(fde.instructions));

    fdeVec.push_back(std::move(fde));
    return true;
}

void Cfi::scan() {
    std::string_view unparsed = secData();
    while (!unparsed.empty()) {
        uint32_t startPosition = unparsed.data() - secData().data();  // section relative
        fmt::print("\n[CFI] entry at {:#10x} (.eh_frame + {:#x})\n",
                unparsed.data() - elfImage().data(), startPosition);
        uint64_t length = decodeDwarf(DW_EH_PE_udata4, unparsed);
        switch (length) {
            case 0:
                fmt::print("[TERMINATOR, length==0]\n");
                return;
            case 0xffff'ffff:
                // Replace Length with ExtendedLength.
                length = decodeDwarf(DW_EH_PE_udata8, unparsed);
                break;
        }
        std::string_view cieData = unparsed.substr(0, length);
        unparsed = unparsed.substr(length);
        fmt::print("  .data[{:#x}]: {}\n", cieData.size(), hexString(cieData));
        uint32_t cieId = decodeDwarf(DW_EH_PE_udata4, cieData);
        fmt::print("  cieId: {:#x}\n", cieId);

        if (cieId == 0) {
            // Continue as a CIE
            if (!scanCie(cieData, startPosition))
                return;
        } else {
            // Continue as an FDE
            if (!scanFde(cieData, startPosition, cieId))
                return;
        }
    }
}

class ElfScanner {
public:
    void scanElfHeader(Elf& elf) {
        memcpy(&elf.eHeader, &elf.image[0], sizeof(elf.eHeader));

        const unsigned char* ident = elf.eHeader.e_ident;
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

        if (verboseElfDecode) {
            auto hdrDump = [](const char* field, auto x) {
                std::cout << "  ." << field << ": " << hexInt(x) << "\n";
            };
#define HDRF_(f) hdrDump(#f, elf.eHeader.f);
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

    void scanProgramHeaders(Elf& elf) {
        size_t pho = elf.eHeader.e_phoff;
        elf.pHeaders.reserve(elf.eHeader.e_phnum);
        for (size_t phi = 0; phi < elf.eHeader.e_phnum; ++phi, pho += elf.eHeader.e_phentsize) {
            Elf64_Phdr pHeader;
            if (elf.image.size() <= sizeof(pHeader)) {
                std::cerr << "ELF image (" << elf.image.size() << ") not big enough for pHeader ("
                    << sizeof(pHeader) << ")" << std::endl;
                throw std::runtime_error("ELF too small");
            }
            memcpy(&pHeader, elf.image.data() + pho, sizeof(pHeader));

            if (verboseElfDecode) {
                fmt::print("Segment header #{}, hdrAt: {:#x}\n", phi, pho);
                auto hdrDump = [](const char* field, auto x) { return fmt::print("  .{:<16}: {:#10x}\n", field, x); };
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
            elf.pHeaders.push_back({pho, pHeader});
        }
    }

    void scanSectionHeaders(Elf& elf) {
        size_t sho = elf.eHeader.e_shoff;
        elf.sHeaders.reserve(elf.eHeader.e_shnum);

        for (size_t shi = 0; shi < elf.eHeader.e_shnum; ++shi, sho += elf.eHeader.e_shentsize) {
            Elf64_Shdr sHeader;
            if (elf.image.size() <= sizeof(sHeader)) {
                std::cerr << "ELF image (" << elf.image.size() << ") not big enough for sHeader ("
                    << sizeof(sHeader) << ")" << std::endl;
                throw std::runtime_error("ELF too small");
            }
            memcpy(&sHeader, elf.image.data() + sho, sizeof(sHeader));
            elf.sHeaders.push_back({sho, {}, sHeader});
        }

        // Now go back and give them all names, now that we have seen the string table section.
        const auto& strTabSec = elf.sHeaders[elf.eHeader.e_shstrndx].sHeader;
        const char* strTab = &elf.image[strTabSec.sh_offset];
        for (auto&& s : elf.sHeaders) {
            s.name = std::string(strTab + s.sHeader.sh_name);
        }

        for (size_t shi = 0; shi != elf.sHeaders.size(); ++shi) {
            auto& s = elf.sHeaders[shi];
            fmt::print("Section header #{}, hdrAt: {:#x}, name: \"{}\"\n", shi, s.hdrAt, s.name);
            if (verboseElfDecode) {
                auto hdrDump = [](const char* field, auto x) { fmt::print("  .{:<16}: {:#10x}\n", field, x); };
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
            }
        }
    }

    Elf scan(std::string_view image) {
        Elf elf{image};
        scanElfHeader(elf);
        std::cout << std::endl;
        scanProgramHeaders(elf);
        std::cout << std::endl;
        scanSectionHeaders(elf);
        return elf;
    }
};

int mainInner(std::vector<std::string> args) {
    bool verboseOpt = false;

    fmt::print("args[{}]\n", args.size());
    for (auto& a : args) {
        fmt::print("   \"{}\"\n", a);
    }

    std::string progName = args[0];
    args.erase(args.begin());

    if (auto iter = std::find(args.begin(), args.end(), "-v"); iter != args.end()) {
        verboseOpt = true;
        args.erase(iter);

        fmt::print("args[{}]\n", args.size());
        for (auto& a : args) {
            fmt::print("   \"{}\"\n", a);
        }
    }

    if (args.empty()) {
        fmt::print(stderr, "{}: Missing ELF file name\n", progName);
        return 1;
    }
    std::string elfFile = args[0];
    fmt::print("ELF file: {}\n", elfFile);
    std::string elfImage = slurp(elfFile);
    fmt::print("    size: {0} ({0:#x})\n", elfImage.size());

    ElfScanner scanner{};

    verboseElfDecode = verboseOpt;
    verboseDwarfDecode = verboseOpt;

    Elf elf = scanner.scan(elfImage);

    auto dumpSection = [&](std::string_view name) {
        auto h = elf.findSection(name);
        if (!h)
            throw std::runtime_error(fmt::format("missing \'{}\' section", name));
        fmt::print("Section name: {:18}, sh_offset: {:#10x}, sh_addr: {:#10x}, sh_size: {:#10x}\n",
                   h->name,
                   h->sHeader.sh_offset,
                   h->sHeader.sh_addr,
                   h->sHeader.sh_size);
    };
    dumpSection(kSectionText);
    dumpSection(kSectionGccExceptTable);
    dumpSection(kSectionEhFrame);

    auto ehh = elf.findSection(kSectionEhFrame);
    if (!ehh)
        throw std::runtime_error(fmt::format("missing `{}` section", kSectionEhFrame));
    Cfi cfi(&elf, ehh);
    cfi.scan();
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i)
        args.push_back(argv[i]);
    return mainInner(std::move(args));
}
