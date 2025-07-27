//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

#define DO_API(r, n, p) r (*n) p
#include "il2cpp-api-functions.h"
#undef DO_API

typedef struct Il2CppGlobalMetadataHeader {
    int32_t sanity;
    int32_t version;
    int32_t stringLiteralOffset;
    int32_t stringLiteralCount;
    int32_t stringLiteralDataOffset;
    int32_t stringLiteralDataCount;
    int32_t stringOffset;
    int32_t stringCount;
    int32_t eventsOffset;
    int32_t eventsCount;
    int32_t propertiesOffset;
    int32_t propertiesCount;
    int32_t methodsOffset;
    int32_t methodsCount;
    int32_t parameterDefaultValuesOffset;
    int32_t parameterDefaultValuesCount;
    int32_t fieldDefaultValuesOffset;
    int32_t fieldDefaultValuesCount;
    int32_t fieldAndParameterDefaultValueDataOffset;
    int32_t fieldAndParameterDefaultValueDataCount;
    int32_t fieldMarshaledSizesOffset;
    int32_t fieldMarshaledSizesCount;
    int32_t resourcesOffset;
    int32_t resourcesCount;
    int32_t genericContainersOffset;
    int32_t genericContainersCount;
    int32_t genericParametersOffset;
    int32_t genericParametersCount;
    int32_t nestedTypesOffset;
    int32_t nestedTypesCount;
    int32_t interfacesOffset;
    int32_t interfacesCount;
    int32_t vtableMethodsOffset;
    int32_t vtableMethodsCount;
    int32_t interfaceOffsetsOffset;
    int32_t interfaceOffsetsCount;
    int32_t typeDefinitionsOffset;
    int32_t typeDefinitionsCount;
    int32_t rgctxEntriesOffset;
    int32_t rgctxEntriesCount;
    int32_t imagesOffset;
    int32_t imagesCount;
    int32_t assembliesOffset;
    int32_t assembliesCount;
    int32_t metadataUsageListsOffset;
    int32_t metadataUsageListsCount;
    int32_t metadataUsagePairsOffset;
    int32_t metadataUsagePairsCount;
    int32_t fieldRefsOffset;
    int32_t fieldRefsCount;
    int32_t referencedAssembliesOffset;
    int32_t referencedAssembliesCount;
    int32_t attributesInfoOffset;
    int32_t attributesInfoCount;
    int32_t attributeTypesOffset;
    int32_t attributeTypesCount;
    int32_t unresolvedVirtualCallParameterTypesOffset;
    int32_t unresolvedVirtualCallParameterTypesCount;
    int32_t unresolvedVirtualCallParameterRangesOffset;
    int32_t unresolvedVirtualCallParameterRangesCount;
    int32_t windowsRuntimeTypeNamesOffset;
    int32_t windowsRuntimeTypeNamesSize;
    int32_t exportedTypeDefinitionsOffset;
    int32_t exportedTypeDefinitionsCount;
    int32_t fileSize;
} Il2CppGlobalMetadataHeader;

static uint64_t il2cpp_base = 0;

// --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ И ФУНКЦИИ ДЛЯ СКАНЕРА ---
static sigjmp_buf JMP_BUF;
static bool g_metadata_found = false;

static void sigsegv_handler(int signum, siginfo_t *info, void *ucontext) {
    (void)signum; (void)info; (void)ucontext;
    siglongjmp(JMP_BUF, 1);
}

bool find_and_dump_metadata(const char* outDir, int scan_id) {
    if (g_metadata_found) return true;

    LOGI("--- Starting Scan #%d ---", scan_id);

    const uint32_t EXPECTED_METADATA_SIZE = 38143520;
    const uint32_t METADATA_MAGIC = 0xFAB11BAF;
    LOGI("Searching for magic 0x%X AND exact size %u", METADATA_MAGIC, EXPECTED_METADATA_SIZE);

    struct sigaction new_action, old_action;
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_sigaction = sigsegv_handler;
    new_action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &new_action, &old_action);

    FILE* maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        LOGE("Scan #%d: Failed to open /proc/self/maps.", scan_id);
        sigaction(SIGSEGV, &old_action, NULL);
        return false;
    }

    char line[1024];
    int matches_found = 0;

    while (fgets(line, sizeof(line), maps_file)) {
        uintptr_t region_start, region_end;
        char perms[5];
        if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s", &region_start, &region_end, perms) == 3) {
            if (perms[0] != 'r') continue;
            if (region_end - region_start < EXPECTED_METADATA_SIZE) continue;

            LOGI("Scan #%d: Scanning potential region: [%p, %p]", scan_id, (void*)region_start, (void*)region_end);

            if (sigsetjmp(JMP_BUF, 1) == 0) {
                for (char* ptr = (char*)region_start; ptr <= (char*)region_end - sizeof(uint32_t); ++ptr) {
                    if (*(uint32_t*)ptr == METADATA_MAGIC) {
                        auto potential_header = (Il2CppGlobalMetadataHeader *)ptr;
                        if (potential_header->fileSize == EXPECTED_METADATA_SIZE) {
                            if ((uintptr_t)ptr + EXPECTED_METADATA_SIZE > region_end) continue;

                            LOGI("!!! Scan #%d: MATCH FOUND at %p !!!", scan_id, ptr);
                            std::string filename = "/global-metadata-decrypted.dat";
                            auto metadataPath = std::string(outDir).append(filename);

                            LOGI("Scan #%d: Proceeding to dump %u bytes to %s", scan_id, EXPECTED_METADATA_SIZE, metadataPath.c_str());
                            std::ofstream metadataStream(metadataPath, std::ios::binary);
                            if (metadataStream.is_open()) {
                                metadataStream.write(ptr, EXPECTED_METADATA_SIZE);
                                metadataStream.close();
                                LOGI("--- Scan #%d: SUCCESS! ---", scan_id);
                                matches_found++;
                                g_metadata_found = true;
                                goto end_scan;
                            }
                        }
                    }
                }
            } else {
                LOGW("Scan #%d: A segmentation fault was caught and handled.", scan_id);
            }
        }
    }

    end_scan:
    fclose(maps_file);
    sigaction(SIGSEGV, &old_action, NULL);

    if (!g_metadata_found) {
        LOGE("--- Scan #%d: FAILED. ---", scan_id);
    }
    return g_metadata_found;
}
// --- КОНЕЦ ФУНКЦИИ СКАНЕРА ---

void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}
#include "il2cpp-api-functions.h"
#undef DO_API
}

std::string get_method_modifier(uint32_t flags) {
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "sealed override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) {
            outPut << "virtual ";
        } else {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) {
        outPut << "extern ";
    }
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        if (method->methodPointer) {
            outPut << "\t// RVA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer - il2cpp_base;
            outPut << " VA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer;
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) {
            outPut << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) {
                    outPut << "out ";
                } else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) {
                    outPut << "in ";
                } else {
                    outPut << "ref ";
                }
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) {
                    outPut << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT) {
                    outPut << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            outPut << ", ";
        }
        if (param_count > 0) {
            outPut.seekp(-2, outPut.cur);
        }
        outPut << ") { }\n";
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) {
                outPut << "get; ";
            }
            if (set) {
                outPut << "set; ";
            }
            outPut << "}\n";
        } else {
            if (prop_name) {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            outPut << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) {
        outPut << "[Serializable]\n";
    }
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            outPut << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            outPut << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            outPut << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            outPut << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "static ";
    } else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
    } else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE) {
        outPut << "interface ";
    } else if (is_enum) {
        outPut << "enum ";
    } else if (is_valuetype) {
        outPut << "struct ";
    } else {
        outPut << "class ";
    }
    outPut << il2cpp_class_get_name(klass);
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) {
            extends.emplace_back(il2cpp_class_get_name(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) {
        extends.emplace_back(il2cpp_class_get_name(itf));
    }
    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (int i = 1; i < extends.size(); ++i) {
            outPut << ", " << extends[i];
        }
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    outPut << "}\n";
    return outPut.str();
}

void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_handle: %p", handle);
    init_il2cpp_api(handle);
    if (il2cpp_domain_get_assemblies) {
        Dl_info dlInfo;
        if (dladdr((void *) il2cpp_domain_get_assemblies, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        }
        LOGI("il2cpp_base: %" PRIx64"", il2cpp_base);
    } else {
        LOGE("Failed to initialize il2cpp api.");
        return;
    }
    while (!il2cpp_is_vm_thread(nullptr)) {
        LOGI("Waiting for il2cpp_init...");
        sleep(1);
    }
    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);
}

void il2cpp_dump(const char *outDir) {
    // Этап 1: "Засада" (ДО)
    find_and_dump_metadata(outDir, 1);

    LOGI("Standard dump procedure for dump.cs started...");
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);

    // Этап 2: "Перехват" (ВОВРЕМЯ)
    find_and_dump_metadata(outDir, 2);

    std::stringstream imageOutput;
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }
    std::vector<std::string> outPuts;
    if (il2cpp_image_get_class) {
        LOGI("Version greater than 2018.3");
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    } else {
        LOGI("Version less than 2018.3");
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (!assemblyLoad || !assemblyGetTypes) {
            LOGE("Failed to find reflection methods.");
            return;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            auto image_name = il2cpp_image_get_name(image);
            imageStr << "\n// Dll : " << image_name;
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(nullptr,
                                                                                        assemblyFileName,
                                                                                        nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                    reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;
            for (int j = 0; j < reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
                auto type = il2cpp_class_get_type(klass);
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    }
    LOGI("write dump file");
    auto outPath = std::string(outDir).append("/dump.cs");
    std::ofstream outStream(outPath);
    outStream << imageOutput.str();
    auto count = outPuts.size();
    for (int i = 0; i < count; ++i) {
        outStream << outPuts[i];
    }
    outStream.close();
    LOGI("dump.cs done!");
    // ==================================================================
    // НАЧАЛО НАШЕГО НОВОГО КОДА (v11, "Ядерный вариант")
    // ==================================================================
    LOGI("Attempting to locate metadata block by SANE FILE SIZE scanning...");

    const uint32_t EXPECTED_METADATA_SIZE = 38143520;
    // Задаем диапазон "правдоподобного" размера
    const uint32_t MIN_SANE_SIZE = EXPECTED_METADATA_SIZE - 2048;
    const uint32_t MAX_SANE_SIZE = EXPECTED_METADATA_SIZE + 2048;
    LOGI("Searching for a header with fileSize between %u and %u", MIN_SANE_SIZE, MAX_SANE_SIZE);

    struct sigaction new_action, old_action;
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_sigaction = sigsegv_handler;
    new_action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &new_action, &old_action);

    FILE* maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        LOGE("Failed to open /proc/self/maps. Aborting.");
        sigaction(SIGSEGV, &old_action, NULL);
        return;
    }

    char line[1024];
    char *metadata_base = nullptr;
    uint32_t final_dump_size = 0;

    while (fgets(line, sizeof(line), maps_file)) {
        uintptr_t region_start, region_end;
        char perms[5];
        if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s", &region_start, &region_end, perms) == 3) {
            if (perms[0] != 'r') continue;
            if (region_end - region_start < MIN_SANE_SIZE) continue;

            LOGI("Scanning potential region: [%p, %p]", (void*)region_start, (void*)region_end);

            if (sigsetjmp(JMP_BUF, 1) == 0) {
                for (char* ptr = (char*)region_start; ptr <= (char*)region_end - sizeof(Il2CppGlobalMetadataHeader); ptr += 4) {
                    auto potential_header = (Il2CppGlobalMetadataHeader *)ptr;
                    uint32_t internal_size = potential_header->fileSize;

                    // ГЛАВНАЯ ПРОВЕРКА: Размер "правдоподобен"?
                    if (internal_size >= MIN_SANE_SIZE && internal_size <= MAX_SANE_SIZE) {
                        // ВТОРАЯ ПРОВЕРКА: Блок помещается в регион?
                        if ((uintptr_t)ptr + internal_size > region_end) {
                            continue;
                        }

                        // Если мы здесь, это наш самый вероятный кандидат.
                        LOGI("SANE SIZE and BOUNDS CHECK PASSED at: %p", ptr);
                        LOGI("Header reports size: %u. Magic is: 0x%X", internal_size, potential_header->sanity);
                        metadata_base = ptr;
                        final_dump_size = internal_size;
                        goto found_it;
                    }
                }
            } else {
                LOGW("A segmentation fault was caught and handled. Skipping to next region.");
            }
        }
    }

    found_it:
    fclose(maps_file);
    sigaction(SIGSEGV, &old_action, NULL);

    if (metadata_base) {
        LOGI("Proceeding to dump %u bytes from %p.", final_dump_size, metadata_base);
        auto metadataPath = std::string(outDir).append("/global-metadata-decrypted.dat");
        std::ofstream metadataStream(metadataPath, std::ios::binary);
        if (metadataStream.is_open()) {
            metadataStream.write(metadata_base, final_dump_size);
            metadataStream.close();
            LOGI("SUCCESS! Decrypted metadata saved to %s", metadataPath.c_str());
        } else {
            LOGE("Failed to open %s for writing.", metadataPath.c_str());
        }
    } else {
        LOGE("NUCLEAR SEARCH FAILED. Could not find a memory block with a sane size.");
    }
    // ==================================================================
    // КОНЕЦ НАШЕГО НОВОГО КОДА
    // ==================================================================
    // Этап 3: "Последний шанс" (ПОСЛЕ)
    find_and_dump_metadata(outDir, 3);

    LOGI("Main dump function finished.");
}