#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <algorithm>

// Common definitions
#define EI_NIDENT 16

// ELF Definitions
typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Half;
typedef uint64_t Elf64_Off;
typedef int32_t  Elf64_Sword;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

struct Elf32_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
};

struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
};

struct Elf32_Shdr {
    Elf64_Word    sh_name;
    Elf64_Word    sh_type;
    Elf64_Word    sh_flags;
    Elf64_Addr    sh_addr;
    Elf64_Off     sh_offset;
    Elf64_Word    sh_size;
    Elf64_Word    sh_link;
    Elf64_Word    sh_info;
    Elf64_Word    sh_addralign;
    Elf64_Word    sh_entsize;
};

struct Elf64_Shdr {
    Elf64_Word    sh_name;
    Elf64_Word    sh_type;
    Elf64_Xword   sh_flags;
    Elf64_Addr    sh_addr;
    Elf64_Off     sh_offset;
    Elf64_Xword   sh_size;
    Elf64_Word    sh_link;
    Elf64_Word    sh_info;
    Elf64_Xword   sh_addralign;
    Elf64_Xword   sh_entsize;
};

struct Elf32_Phdr {
    Elf64_Word    p_type;
    Elf64_Off     p_offset;
    Elf64_Addr    p_vaddr;
    Elf64_Addr    p_paddr;
    Elf64_Word    p_filesz;
    Elf64_Word    p_memsz;
    Elf64_Word    p_flags;
    Elf64_Word    p_align;
};

struct Elf64_Phdr {
    Elf64_Word    p_type;
    Elf64_Word    p_flags;
    Elf64_Off     p_offset;
    Elf64_Addr    p_vaddr;
    Elf64_Addr    p_paddr;
    Elf64_Xword   p_filesz;
    Elf64_Xword   p_memsz;
    Elf64_Xword   p_align;
};

// PE Definitions
#pragma pack(push, 1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_SECTION_HEADER {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

class BinaryParser {
private:
    std::vector<uint8_t> fileData;
    bool is64Bit;

    void validateFileSize(size_t required) {
        if (fileData.size() < required) {
            throw std::runtime_error("File too small for expected headers");
        }
    }

    void parseELF() {
        validateFileSize(sizeof(Elf64_Ehdr));

        unsigned char* ident = fileData.data();
        if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
            throw std::runtime_error("Invalid ELF magic number");
        }

        is64Bit = (ident[4] == 2); // 1 = 32-bit, 2 = 64-bit
        bool isLE = (ident[5] == 1); // 1 = LE, 2 = BE

        std::cout << "\nELF Header Information:\n";
        std::cout << "  Class:                             " << (is64Bit ? "64-bit" : "32-bit") << "\n";
        std::cout << "  Data:                              " << (isLE ? "Little Endian" : "Big Endian") << "\n";
        std::cout << "  Version:                           " << static_cast<int>(ident[6]) << "\n";
        std::cout << "  OS/ABI:                            " << static_cast<int>(ident[7]) << "\n";
        std::cout << "  ABI Version:                       " << static_cast<int>(ident[8]) << "\n";

        if (is64Bit) {
            Elf64_Ehdr* header = reinterpret_cast<Elf64_Ehdr*>(fileData.data());
            printELFHeaderCommon(header);
            parseELFSectionHeaders<Elf64_Shdr>(header);
            parseELFProgramHeaders<Elf64_Phdr>(header);
        } else {
            Elf32_Ehdr* header = reinterpret_cast<Elf32_Ehdr*>(fileData.data());
            printELFHeaderCommon(header);
            parseELFSectionHeaders<Elf32_Shdr>(header);
            parseELFProgramHeaders<Elf32_Phdr>(header);
        }
    }

    template<typename T>
    void printELFHeaderCommon(T* header) {
        std::cout << "  Type:                              " << header->e_type << "\n";
        std::cout << "  Machine:                           " << header->e_machine << "\n";
        std::cout << "  Version:                           " << header->e_version << "\n";
        std::cout << "  Entry point address:               0x" << std::hex << header->e_entry << std::dec << "\n";
        std::cout << "  Start of program headers:          " << header->e_phoff << "\n";
        std::cout << "  Start of section headers:          " << header->e_shoff << "\n";
        std::cout << "  Flags:                             " << header->e_flags << "\n";
        std::cout << "  Size of this header:               " << header->e_ehsize << "\n";
        std::cout << "  Size of program headers:          " << header->e_phentsize << "\n";
        std::cout << "  Number of program headers:        " << header->e_phnum << "\n";
        std::cout << "  Size of section headers:          " << header->e_shentsize << "\n";
        std::cout << "  Number of section headers:        " << header->e_shnum << "\n";
        std::cout << "  Section header string table index: " << header->e_shstrndx << "\n";
    }

    template<typename T>
    void parseELFSectionHeaders(Elf64_Ehdr* header) {
        if (header->e_shnum == 0 || header->e_shentsize == 0) {
            std::cout << "\nNo section headers present\n";
            return;
        }

        size_t shoff = header->e_shoff;
        size_t shentsize = header->e_shentsize;
        size_t shnum = header->e_shnum;

        validateFileSize(shoff + (shnum * shentsize));

        std::cout << "\nSection Headers:\n";
        std::cout << "  [Nr] Name              Type            Address          Offset\n";
        std::cout << "       Size              EntSize         Flags  Link  Info  Align\n";

        // Get section header string table
        const char* shstrtab = nullptr;
        if (header->e_shstrndx < shnum) {
            T* shstrtab_hdr = reinterpret_cast<T*>(fileData.data() + shoff + (header->e_shstrndx * shentsize));
            if (shstrtab_hdr->sh_offset < fileData.size()) {
                shstrtab = reinterpret_cast<const char*>(fileData.data() + shstrtab_hdr->sh_offset);
            }
        }

        for (size_t i = 0; i < shnum; i++) {
            T* shdr = reinterpret_cast<T*>(fileData.data() + shoff + (i * shentsize));

            const char* name = "?";
            if (shstrtab && shdr->sh_name != 0) {
                name = shstrtab + shdr->sh_name;
                if (reinterpret_cast<const uint8_t*>(name) >= fileData.data() + fileData.size()) {
                    name = "?";
                }
            }

            std::cout << "  [" << std::setw(2) << i << "] "
                      << std::left << std::setw(17) << name << std::right << " "
                      << std::setw(15) << shdr->sh_type << " "
                      << "0x" << std::setw(16) << std::setfill('0') << shdr->sh_addr << " "
                      << std::setfill(' ') << std::setw(8) << shdr->sh_offset << "\n"
                      << "       " << std::setw(16) << shdr->sh_size << " "
                      << std::setw(15) << shdr->sh_entsize << " "
                      << std::setw(6) << shdr->sh_flags << " "
                      << std::setw(5) << shdr->sh_link << " "
                      << std::setw(5) << shdr->sh_info << " "
                      << std::setw(5) << shdr->sh_addralign << "\n";
        }
    }

    template<typename T>
    void parseELFProgramHeaders(Elf64_Ehdr* header) {
        if (header->e_phnum == 0 || header->e_phentsize == 0) {
            std::cout << "\nNo program headers present\n";
            return;
        }

        size_t phoff = header->e_phoff;
        size_t phentsize = header->e_phentsize;
        size_t phnum = header->e_phnum;

        validateFileSize(phoff + (phnum * phentsize));

        std::cout << "\nProgram Headers:\n";
        std::cout << "  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align\n";

        for (size_t i = 0; i < phnum; i++) {
            T* phdr = reinterpret_cast<T*>(fileData.data() + phoff + (i * phentsize));

            std::cout << "  " << std::left << std::setw(14) << phdr->p_type << std::right << " "
                      << "0x" << std::setw(6) << std::setfill('0') << phdr->p_offset << " "
                      << "0x" << std::setw(16) << phdr->p_vaddr << " "
                      << "0x" << std::setw(16) << phdr->p_paddr << " "
                      << "0x" << std::setw(6) << phdr->p_filesz << " "
                      << "0x" << std::setw(6) << phdr->p_memsz << " "
                      << std::setfill(' ') << std::setw(3) << (phdr->p_flags & 0x7) << " "
                      << "0x" << phdr->p_align << "\n";
        }
    }

    void parsePE() {
        validateFileSize(sizeof(IMAGE_DOS_HEADER));

        IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData.data());
        if (dosHeader->e_magic != 0x5A4D) { // "MZ"
            throw std::runtime_error("Invalid DOS header magic number");
        }

        uint32_t peOffset = dosHeader->e_lfanew;
        validateFileSize(peOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));

        uint32_t peSignature = *reinterpret_cast<uint32_t*>(fileData.data() + peOffset);
        if (peSignature != 0x00004550) { // "PE\0\0"
            throw std::runtime_error("Invalid PE signature");
        }

        IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(fileData.data() + peOffset + 4);
        is64Bit = false;

        // Check if this is a PE32+ (64-bit) executable
        if (fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64) - sizeof(IMAGE_DATA_DIRECTORY[16])) {
            uint16_t magic = *reinterpret_cast<uint16_t*>(fileData.data() + peOffset + 4 + sizeof(IMAGE_FILE_HEADER));
            is64Bit = (magic == 0x20b); // PE32+ magic number
        }

        printPEHeaderInfo(peOffset, fileHeader);
        parsePESectionHeaders(peOffset, fileHeader);
    }

    void printPEHeaderInfo(uint32_t peOffset, IMAGE_FILE_HEADER* fileHeader) {
        std::cout << "\nPE Header Information:\n";
        std::cout << "  Machine:              0x" << std::hex << fileHeader->Machine << std::dec << "\n";
        std::cout << "  Number of sections:   " << fileHeader->NumberOfSections << "\n";
        std::cout << "  Timestamp:            " << fileHeader->TimeDateStamp << " ("
                  << std::asctime(std::localtime(reinterpret_cast<const time_t*>(&fileHeader->TimeDateStamp))) << ")";
        std::cout << "  Pointer to symtab:    " << fileHeader->PointerToSymbolTable << "\n";
        std::cout << "  Number of symbols:    " << fileHeader->NumberOfSymbols << "\n";
        std::cout << "  Optional header size: " << fileHeader->SizeOfOptionalHeader << "\n";
        std::cout << "  Characteristics:      0x" << std::hex << fileHeader->Characteristics << std::dec << "\n";

        if (fileHeader->SizeOfOptionalHeader > 0) {
            if (is64Bit) {
                IMAGE_OPTIONAL_HEADER64* optionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
                    fileData.data() + peOffset + 4 + sizeof(IMAGE_FILE_HEADER));

                std::cout << "\nOptional Header (PE32+):\n";
                std::cout << "  Magic:                      0x" << std::hex << optionalHeader->Magic << std::dec << "\n";
                std::cout << "  Linker version:             " << static_cast<int>(optionalHeader->MajorLinkerVersion) << "."
                          << static_cast<int>(optionalHeader->MinorLinkerVersion) << "\n";
                std::cout << "  Size of code:               " << optionalHeader->SizeOfCode << "\n";
                std::cout << "  Size of initialized data:   " << optionalHeader->SizeOfInitializedData << "\n";
                std::cout << "  Size of uninitialized data: " << optionalHeader->SizeOfUninitializedData << "\n";
                std::cout << "  Entry point:               0x" << std::hex << optionalHeader->AddressOfEntryPoint << std::dec << "\n";
                std::cout << "  Base of code:              0x" << std::hex << optionalHeader->BaseOfCode << std::dec << "\n";
                std::cout << "  Image base:                0x" << std::hex << optionalHeader->ImageBase << std::dec << "\n";
            } else {
                IMAGE_OPTIONAL_HEADER32* optionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(
                    fileData.data() + peOffset + 4 + sizeof(IMAGE_FILE_HEADER));

                std::cout << "\nOptional Header (PE32):\n";
                std::cout << "  Magic:                      0x" << std::hex << optionalHeader->Magic << std::dec << "\n";
                std::cout << "  Linker version:             " << static_cast<int>(optionalHeader->MajorLinkerVersion) << "."
                          << static_cast<int>(optionalHeader->MinorLinkerVersion) << "\n";
                std::cout << "  Size of code:               " << optionalHeader->SizeOfCode << "\n";
                std::cout << "  Size of initialized data:   " << optionalHeader->SizeOfInitializedData << "\n";
                std::cout << "  Size of uninitialized data: " << optionalHeader->SizeOfUninitializedData << "\n";
                std::cout << "  Entry point:               0x" << std::hex << optionalHeader->AddressOfEntryPoint << std::dec << "\n";
                std::cout << "  Base of code:              0x" << std::hex << optionalHeader->BaseOfCode << std::dec << "\n";
                std::cout << "  Base of data:              0x" << std::hex << optionalHeader->BaseOfData << std::dec << "\n";
                std::cout << "  Image base:                0x" << std::hex << optionalHeader->ImageBase << std::dec << "\n";
            }
        }
    }

    void parsePESectionHeaders(uint32_t peOffset, IMAGE_FILE_HEADER* fileHeader) {
        if (fileHeader->NumberOfSections == 0) {
            std::cout << "\nNo sections present\n";
            return;
        }

        uint32_t sectionOffset = peOffset + 4 + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader;
        validateFileSize(sectionOffset + (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));

        std::cout << "\nSection Headers:\n";
        std::cout << "  [Nr] Name               VirtAddr    VirtSize    RawAddr     RawSize     Flags\n";

        for (int i = 0; i < fileHeader->NumberOfSections; i++) {
            IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                fileData.data() + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)));

            std::cout << "  [" << std::setw(2) << i << "] "
                      << std::left << std::setw(19) << std::string(section->Name, 8) << std::right << " "
                      << "0x" << std::setw(8) << std::setfill('0') << section->VirtualAddress << "  "
                      << "0x" << std::setw(8) << section->Misc.VirtualSize << "  "
                      << "0x" << std::setw(8) << section->PointerToRawData << "  "
                      << "0x" << std::setw(8) << section->SizeOfRawData << "  "
                      << std::setfill(' ') << "0x" << std::hex << section->Characteristics << std::dec << "\n";
        }
    }

public:
    BinaryParser(const std::string& filename) : is64Bit(false) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + filename);
        }

        std::streamsize size = file.tellg();
        if (size <= 0) {
            throw std::runtime_error("Empty or invalid file: " + filename);
        }

        file.seekg(0, std::ios::beg);
        fileData.resize(size);

        if (!file.read(reinterpret_cast<char*>(fileData.data()), size)) {
            throw std::runtime_error("Failed to read file: " + filename);
        }

        if (fileData.size() < 4) {
            throw std::runtime_error("File too small to be a valid executable");
        }
    }

    void parse() {
        try {
            // Check for PE first
            if (fileData.size() >= sizeof(IMAGE_DOS_HEADER) {
                IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData.data());
                if (dosHeader->e_magic == 0x5A4D) { // "MZ"
                    parsePE();
                    return;
                }
            }

            // Check for ELF
            if (fileData.size() >= EI_NIDENT) {
                unsigned char* ident = fileData.data();
                if (ident[0] == 0x7F && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F') {
                    parseELF();
                    return;
                }
            }

            throw std::runtime_error("File is neither a valid PE nor ELF executable");
        } catch (const std::exception& e) {
            throw std::runtime_error(std::string("Parsing failed: ") + e.what());
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <executable_file>\n";
        return 1;
    }

    try {
        BinaryParser parser(argv[1]);
        parser.parse();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}