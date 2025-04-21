#include <iostream>
#include <vector>
#include <map>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <memory>
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <capstone/capstone.h>

class VirtualTableAnalyzer {
public:
    struct VTableInfo {
        uintptr_t address;
        std::vector<uintptr_t> functions;
        std::string module_name;
        std::string class_name;
        std::map<uintptr_t, std::vector<uintptr_t>> references;
        std::map<uintptr_t, std::string> function_disassembly;
    };

    VirtualTableAnalyzer() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone");
        }
        cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
    }

    ~VirtualTableAnalyzer() {
        cs_close(&capstone_handle);
    }

    void analyze_module(const std::string& module_path) {
        void* handle = dlopen(module_path.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (!handle) {
            throw std::runtime_error("Failed to open module: " + std::string(dlerror()));
        }

        struct link_map* map;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0) {
            dlclose(handle);
            throw std::runtime_error("Failed to get module info");
        }

        module_base_ = reinterpret_cast<uintptr_t>(map->l_addr);
        analyze_memory_range(module_base_,
                           map->l_ld ? reinterpret_cast<uintptr_t>(map->l_ld) : 0,
                           module_path);

        // Second pass for cross-references
        for (auto& [addr, info] : vtables_) {
            find_vtable_references(addr);
            analyze_rtti(addr);
            disassemble_functions(info);
        }

        dlclose(handle);
    }

    const std::map<uintptr_t, VTableInfo>& get_virtual_tables() const {
        return vtables_;
    }

    void dump_analysis(std::ostream& os) const {
        for (const auto& [addr, info] : vtables_) {
            os << "=== Virtual Table at 0x" << std::hex << addr << " ===\n";
            os << "Module: " << info.module_name << "\n";
            os << "Class: " << (info.class_name.empty() ? "Unknown" : info.class_name) << "\n\n";

            os << "Virtual Functions:\n";
            for (size_t i = 0; i < info.functions.size(); ++i) {
                os << "  [" << i << "] 0x" << std::hex << info.functions[i];

                auto it = info.function_disassembly.find(info.functions[i]);
                if (it != info.function_disassembly.end()) {
                    os << "  " << it->second;
                }
                os << "\n";
            }

            os << "\nCross-References:\n";
            for (const auto& [ref_addr, refs] : info.references) {
                os << "  0x" << std::hex << ref_addr << " references:\n";
                for (auto ref : refs) {
                    os << "    -> 0x" << std::hex << ref << "\n";
                }
            }
            os << "\n";
        }
    }

private:
    std::map<uintptr_t, VTableInfo> vtables_;
    uintptr_t module_base_ = 0;
    csh capstone_handle;

    bool is_valid_address(uintptr_t addr) {
        return addr >= 0x1000 && addr < 0x00007fffffffffff;
    }

    bool is_executable_address(uintptr_t addr) {
        Dl_info info;
        return dladdr(reinterpret_cast<void*>(addr), &info) != 0;
    }

    void analyze_memory_range(uintptr_t start, uintptr_t end, const std::string& module_name) {
        const size_t page_size = sysconf(_SC_PAGESIZE);
        const uintptr_t page_mask = ~(page_size - 1);
        uintptr_t start_page = start & page_mask;
        uintptr_t end_page = (end + page_size - 1) & page_mask;

        for (uintptr_t page = start_page; page < end_page; page += page_size) {
            void* page_ptr = reinterpret_cast<void*>(page);
            if (mprotect(page_ptr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                continue;
            }
            scan_for_vtables(page, page + page_size, module_name);
        }
    }

    void scan_for_vtables(uintptr_t start, uintptr_t end, const std::string& module_name) {
        for (uintptr_t ptr = start; ptr < end - sizeof(uintptr_t); ptr += sizeof(uintptr_t)) {
            uintptr_t potential_vtable = *reinterpret_cast<uintptr_t*>(ptr);
            if (!is_valid_address(potential_vtable)) continue;

            std::vector<uintptr_t> functions;
            if (check_vtable_candidate(potential_vtable, functions)) {
                vtables_[potential_vtable] = {
                    potential_vtable,
                    functions,
                    module_name,
                    "",
                    {},
                    {}
                };
            }
        }
    }

    bool check_vtable_candidate(uintptr_t vtable_addr, std::vector<uintptr_t>& functions) {
        functions.clear();
        for (int i = 0; i < 16; ++i) {
            uintptr_t func_ptr = *reinterpret_cast<uintptr_t*>(vtable_addr + i * sizeof(uintptr_t));
            if (!is_valid_address(func_ptr) || !is_executable_address(func_ptr)) break;
            functions.push_back(func_ptr);
        }
        return functions.size() >= 3;
    }

    void analyze_rtti(uintptr_t vtable_addr) {
        uintptr_t rtti_ptr = vtable_addr - sizeof(uintptr_t);
        if (!is_valid_address(rtti_ptr)) return;

        uintptr_t type_info_addr = *reinterpret_cast<uintptr_t*>(rtti_ptr);
        if (!is_valid_address(type_info_addr)) return;

        // Typeinfo structure:
        // ptr to vtable of typeinfo
        // ptr to typeinfo name
        uintptr_t name_ptr = *reinterpret_cast<uintptr_t*>(type_info_addr + sizeof(uintptr_t));
        if (!is_valid_address(name_ptr)) return;

        const char* name = reinterpret_cast<const char*>(name_ptr);
        if (name) {
            // Demangle the name if needed
            vtables_[vtable_addr].class_name = demangle_name(name);
        }
    }

    std::string demangle_name(const char* mangled) {
        // Simple demangling - in production use __cxa_demangle
        std::string name(mangled);
        // Remove leading numbers (GCC style)
        while (!name.empty() && isdigit(name[0])) {
            name.erase(0, 1);
        }
        return name;
    }

    void find_vtable_references(uintptr_t vtable_addr) {
        for (const auto& [other_addr, other_info] : vtables_) {
            if (other_addr == vtable_addr) continue;

            std::vector<uintptr_t> refs;
            for (uintptr_t func_addr : other_info.functions) {
                if (is_reference_to_vtable(func_addr, vtable_addr)) {
                    refs.push_back(func_addr);
                }
            }

            if (!refs.empty()) {
                vtables_[vtable_addr].references[other_addr] = refs;
            }
        }
    }

    bool is_reference_to_vtable(uintptr_t func_addr, uintptr_t vtable_addr) {
        // Disassemble function and look for references to the vtable
        const uint8_t* code = reinterpret_cast<const uint8_t*>(func_addr);
        size_t code_size = 64; // Check first 64 bytes
        uint64_t address = func_addr;
        cs_insn* insn = cs_malloc(capstone_handle);

        while (cs_disasm_iter(capstone_handle, &code, &code_size, &address, insn)) {
            for (int i = 0; i < insn->detail->x86.op_count; i++) {
                cs_x86_op* op = &insn->detail->x86.operands[i];
                if (op->type == X86_OP_IMM) {
                    if (op->imm == static_cast<int64_t>(vtable_addr)) {
                        cs_free(insn, 1);
                        return true;
                    }
                }
            }
        }

        cs_free(insn, 1);
        return false;
    }

    void disassemble_functions(VTableInfo& info) {
        for (uintptr_t func_addr : info.functions) {
            const uint8_t* code = reinterpret_cast<const uint8_t*>(func_addr);
            size_t code_size = 128; // First 128 bytes
            uint64_t address = func_addr;
            cs_insn* insn;
            size_t count = cs_disasm(capstone_handle, code, code_size, address, 0, &insn);

            if (count > 0) {
                std::stringstream ss;
                for (size_t i = 0; i < std::min(count, static_cast<size_t>(3)); i++) {
                    ss << insn[i].mnemonic << " " << insn[i].op_str;
                    if (i < 2) ss << " | ";
                }
                info.function_disassembly[func_addr] = ss.str();
                cs_free(insn, count);
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary> [output_file]\n";
        return 1;
    }

    try {
        VirtualTableAnalyzer analyzer;
        analyzer.analyze_module(argv[1]);

        if (argc > 2) {
            std::ofstream out_file(argv[2]);
            if (!out_file) {
                throw std::runtime_error("Failed to open output file");
            }
            analyzer.dump_analysis(out_file);
        } else {
            analyzer.dump_analysis(std::cout);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}