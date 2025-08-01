// module/src/main/cpp/il2cpp_dump.cpp

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <cinttypes>
#include <thread>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

#define DO_API(r, n, p) r (*n) p
#include "il2cpp-api-functions.h"
#undef DO_API

// Структура заголовка метаданных
struct Il2CppGlobalMetadataHeader
{
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
    int32_t parametersOffset;
    int32_t parametersCount;
    int32_t fieldsOffset;
    int32_t fieldsCount;
    int32_t genericParametersOffset;
    int32_t genericParametersCount;
    int32_t genericParameterConstraintsOffset;
    int32_t genericParameterConstraintsCount;
    int32_t genericContainersOffset;
    int32_t genericContainersCount;
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
    int32_t windowsRuntimeStringsOffset;
    int32_t windowsRuntimeStringsSize;
    int32_t exportedTypeDefinitionsOffset;
    int32_t exportedTypeDefinitionsCount;
};

static uint64_t il2cpp_base = 0;

void il2cpp_api_init_from_handle(void *handle) {
    if (!handle) return;
#define DO_API(r, n, p) n = (r (*) p)xdl_sym(handle, #n, nullptr)
#include "il2cpp-api-functions.h"
#undef DO_API
}

void il2cpp_dump(const char *outDir) {
    LOGI("start il2cpp dump (address dump)");
    std::string out_path(outDir);
    out_path += "/dump.cs";
    std::ofstream out(out_path, std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        LOGE("Failed to open dump.cs");
        return;
    }

    auto domain = il2cpp_domain_get();
    if (!domain) {
        LOGE("il2cpp_dump failed: domain is null.");
        return;
    }
    size_t size;
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        auto image_name = il2cpp_image_get_name(image);
        out << "// " << image_name << std::endl;
        auto classCount = il2cpp_image_get_class_count(image);
        for (int j = 0; j < classCount; ++j) {
            auto klass = const_cast<Il2CppClass *>(il2cpp_image_get_class(image, j));
            auto namespaze = il2cpp_class_get_namespace(klass);
            auto class_name = il2cpp_class_get_name(klass);
            if (*namespaze) {
                out << "namespace " << namespaze << " {" << std::endl;
            }
            out << "class " << class_name << " {" << std::endl;
            //fields
            out << "\t// Fields\n";
            void *iter = nullptr;
            while (auto field = il2cpp_class_get_fields(klass, &iter)) {
                auto field_name = il2cpp_field_get_name(field);
                auto offset = il2cpp_field_get_offset(field);
                auto type = il2cpp_field_get_type(field);
                auto flags = il2cpp_field_get_flags(field);
                out << "\t";
                if (flags & FIELD_ATTRIBUTE_STATIC) {
                    out << "static ";
                }
                auto type_name = il2cpp_type_get_name(type);
                out << type_name << " " << field_name << "; // 0x" << std::hex << offset << std::dec << std::endl;
                free(type_name);
            }
            //methods
            out << "\n\t// Methods\n";
            iter = nullptr;
            while (auto method = il2cpp_class_get_methods(klass, &iter)) {
                auto method_name = il2cpp_method_get_name(method);
                if(method->methodPointer) {
                    auto RVA = (uint64_t) method->methodPointer - il2cpp_base;
                    auto offset = (uint64_t) method->methodPointer;
                    out << "\t";
                    auto ret_type_name = il2cpp_type_get_name(il2cpp_method_get_return_type(method));
                    out << ret_type_name << " " << method_name << "()";
                    free(ret_type_name);
                    out << "; // RVA: 0x" << std::hex << RVA << " Offset: 0x" << offset << std::dec << std::endl;
                }
            }
            out << "}" << std::endl;
            if (*namespaze) {
                out << "}" << std::endl;
            }
        }
    }
    out.close();
    LOGI("il2cpp address dump finished");
}

void dump_thread_func(const char* game_data_dir) {
    LOGI("dump_thread_func started in thread %d", gettid());

    // 1. Ожидаем загрузки libil2cpp.so
    void *handle = nullptr;
    do {
        handle = xdl_open("libil2cpp.so", 0);
        if (handle) break;
        sleep(1);
    } while (true);
    LOGI("libil2cpp.so handle: %p", handle);

    // 2. Находим базовый адрес и размер библиотеки
    xdl_info_t dlInfo;
    void *xdl_cache = nullptr;
    if (xdl_addr(xdl_sym(handle, "il2cpp_init", nullptr), &dlInfo, &xdl_cache)) {
        il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        LOGI("il2cpp_base: %" PRIx64"", il2cpp_base);
    } else {
        LOGE("Failed to get il2cpp_base address.");
        xdl_addr_clean(&xdl_cache);
        return;
    }

    size_t lib_size = 0;
    for(int i = 0; i < dlInfo.dlpi_phnum; ++i) {
        const ElfW(Phdr)* phdr = &dlInfo.dlpi_phdr[i];
        // Ищем самый большой загружаемый сегмент, это и будет примерный размер библиотеки
        if (phdr->p_type == PT_LOAD) {
            if(phdr->p_memsz > lib_size) {
                lib_size = phdr->p_memsz;
            }
        }
    }
    // Выравниваем размер до страницы памяти
    lib_size = (lib_size + getpagesize() - 1) & ~(getpagesize() - 1);

    if (lib_size == 0) {
        LOGE("Could not determine library size for dumping.");
        xdl_addr_clean(&xdl_cache);
        return;
    }
    LOGI("Library size for dump: %zu bytes", lib_size);

    // --- НОВЫЙ БЛОК: ДАМП libil2cpp.so ИЗ ПАМЯТИ ---
    std::string lib_dump_path(game_data_dir);
    lib_dump_path += "/libil2cpp_dumped.so";
    LOGI("Dumping in-memory libil2cpp.so to: %s", lib_dump_path.c_str());
    std::ofstream lib_file(lib_dump_path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (lib_file.is_open()) {
        lib_file.write(reinterpret_cast<const char*>(il2cpp_base), lib_size);
        lib_file.close();
        LOGI("Successfully dumped libil2cpp.so from memory!");
    } else {
        LOGE("Failed to open file for writing libil2cpp.so dump.");
    }
    // --- КОНЕЦ НОВОГО БЛОКА ---

    LOGI("Scanning memory range: 0x%" PRIx64 " to 0x%" PRIx64, il2cpp_base, il2cpp_base + lib_size);

    // 3. Находим указатели на метаданные
    // Сначала пробуем через dsym (быстрее, но может не найти стрипнутые символы)
    void* s_GlobalMetadata_ptr = xdl_dsym(handle, "s_GlobalMetadata", nullptr);
    void* s_GlobalMetadataHeader_ptr = xdl_dsym(handle, "s_GlobalMetadataHeader", nullptr);

    // Если не нашли, пробуем через sym (медленнее, но ищет в полной таблице символов)
    if (!s_GlobalMetadata_ptr) {
        LOGI("s_GlobalMetadata not found with dsym, trying with sym...");
        s_GlobalMetadata_ptr = xdl_sym(handle, "s_GlobalMetadata", nullptr);
    }
    if (!s_GlobalMetadataHeader_ptr) {
        LOGI("s_GlobalMetadataHeader not found with dsym, trying with sym...");
        s_GlobalMetadataHeader_ptr = xdl_sym(handle, "s_GlobalMetadataHeader", nullptr);
    }

    if (!s_GlobalMetadata_ptr || !s_GlobalMetadataHeader_ptr) {
        LOGE("Could not find s_GlobalMetadata or s_GlobalMetadataHeader symbols.");
        xdl_addr_clean(&xdl_cache);
        return;
    }
    LOGI("Found s_GlobalMetadata and s_GlobalMetadataHeader pointers.");

    // 4. Ожидаем, пока il2cpp_init не отработает
    Il2CppGlobalMetadataHeader* header = nullptr;
    bool sanity_ok = false;
    int wait_time = 0;
    const int max_wait_time = 60; // Ждем максимум 60 секунд

    LOGI("Waiting for il2cpp_init to complete by polling metadata header...");
    while (wait_time < max_wait_time) {
        header = *(Il2CppGlobalMetadataHeader**)s_GlobalMetadataHeader_ptr;
        if (header && header->sanity == 0xFAB11BAF) {
            sanity_ok = true;
            break;
        }
        sleep(1);
        wait_time++;
    }

    if (!sanity_ok) {
        LOGE("Timed out waiting for il2cpp_init. Metadata header sanity check failed.");
        xdl_addr_clean(&xdl_cache);
        return;
    }

    LOGI("il2cpp_init completed. Proceeding with dump.");

    // 5. Дампим расшифрованные метаданные
    void* metadata = *(void**)s_GlobalMetadata_ptr;
    size_t metadata_size = header->exportedTypeDefinitionsOffset + (header->exportedTypeDefinitionsCount * sizeof(int32_t));

    LOGI("Metadata Version: %d, Size: %zu bytes", header->version, metadata_size);

    if (metadata && metadata_size > 0) {
        std::string out_path(game_data_dir);
        out_path += "/global-metadata-decrypted.dat";

        LOGI("Dumping decrypted metadata to: %s", out_path.c_str());
        std::ofstream metadata_file(out_path, std::ios::binary | std::ios::out | std::ios::trunc);
        if (metadata_file.is_open()) {
            metadata_file.write(static_cast<const char*>(metadata), metadata_size);
            metadata_file.close();
            LOGI("Successfully dumped decrypted metadata!");
        } else {
            LOGE("Failed to open file for writing decrypted metadata.");
        }
    } else {
        LOGE("Metadata pointer or size is invalid.");
    }

    // 6. Инициализируем API и дампим адреса
    il2cpp_api_init_from_handle(handle);
    if (il2cpp_domain_get) {
        il2cpp_dump(game_data_dir);
    } else {
        LOGE("Failed to initialize il2cpp api for address dump.");
    }

    // Очищаем кэш после использования
    xdl_addr_clean(&xdl_cache);
}

// Эта функция вызывается из hack.cpp
void start_dump_process(const char* game_data_dir) {
    // Запускаем всю логику в отдельном потоке, чтобы не блокировать игру
    std::thread(dump_thread_func, game_data_dir).detach();
}