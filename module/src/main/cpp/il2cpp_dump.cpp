// module/src/main/cpp/il2cpp_dump.cpp

#include "il2cpp_dump.h"
#include "include/dobby.h"
#include <dlfcn.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <cinttypes>
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
    int32_t stringLiteralOffset; // stringLiteral_v21.json
    int32_t stringLiteralCount;
    int32_t stringLiteralDataOffset;
    int32_t stringLiteralDataCount;
    int32_t stringOffset; // string_v21.json
    int32_t stringCount;
    int32_t eventsOffset; // events_v21.json
    int32_t eventsCount;
    int32_t propertiesOffset; // properties_v21.json
    int32_t propertiesCount;
    int32_t methodsOffset; // methods_v21.json
    int32_t methodsCount;
    int32_t parameterDefaultValuesOffset; // parameterDefaultValues_v21.json
    int32_t parameterDefaultValuesCount;
    int32_t fieldDefaultValuesOffset; // fieldDefaultValues_v21.json
    int32_t fieldDefaultValuesCount;
    int32_t fieldAndParameterDefaultValueDataOffset; // fieldAndParameterDefaultValueData_v21.json
    int32_t fieldAndParameterDefaultValueDataCount;
    int32_t fieldMarshaledSizesOffset; // fieldMarshaledSizes_v21.json
    int32_t fieldMarshaledSizesCount;
    int32_t parametersOffset; // parameters_v21.json
    int32_t parametersCount;
    int32_t fieldsOffset; // fields_v21.json
    int32_t fieldsCount;
    int32_t genericParametersOffset; // genericParameters_v21.json
    int32_t genericParametersCount;
    int32_t genericParameterConstraintsOffset; // genericParameterConstraints_v21.json
    int32_t genericParameterConstraintsCount;
    int32_t genericContainersOffset; // genericContainers_v21.json
    int32_t genericContainersCount;
    int32_t nestedTypesOffset; // nestedTypes_v21.json
    int32_t nestedTypesCount;
    int32_t interfacesOffset; // interfaces_v21.json
    int32_t interfacesCount;
    int32_t vtableMethodsOffset; // vtableMethods_v21.json
    int32_t vtableMethodsCount;
    int32_t interfaceOffsetsOffset; // interfaceOffsets_v21.json
    int32_t interfaceOffsetsCount;
    int32_t typeDefinitionsOffset; // typeDefinitions_v21.json
    int32_t typeDefinitionsCount;
    int32_t imagesOffset; // images_v21.json
    int32_t imagesCount;
    int32_t assembliesOffset; // assemblies_v21.json
    int32_t assembliesCount;
    int32_t metadataUsageListsOffset; // metadataUsageLists_v21.json
    int32_t metadataUsageListsCount;
    int32_t metadataUsagePairsOffset; // metadataUsagePairs_v21.json
    int32_t metadataUsagePairsCount;
    int32_t fieldRefsOffset; // fieldRefs_v21.json
    int32_t fieldRefsCount;
    int32_t referencedAssembliesOffset; // referencedAssemblies_v21.json
    int32_t referencedAssembliesCount;
    int32_t attributesInfoOffset; // attributesInfo_v21.json
    int32_t attributesInfoCount;
    int32_t attributeTypesOffset; // attributeTypes_v21.json
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
static const char* g_game_data_dir = nullptr;

// Указатель на оригинальную функцию il2cpp_init
static int (*orig_il2cpp_init)(const char* domain_name);

int hook_il2cpp_init(const char* domain_name) {
    LOGI("hook_il2cpp_init called. Calling original il2cpp_init...");
    int result = orig_il2cpp_init(domain_name);
    LOGI("Original il2cpp_init finished.");

    // Теперь, когда движок инициализирован, можно безопасно работать с его данными
    // и вызывать наш дамп.

    // Сначала дампим расшифрованные метаданные
    void* s_GlobalMetadata_ptr = xdl_dsym((void*)il2cpp_base, "s_GlobalMetadata", nullptr);
    void* s_GlobalMetadataHeader_ptr = xdl_dsym((void*)il2cpp_base, "s_GlobalMetadataHeader", nullptr);

    if (s_GlobalMetadata_ptr && s_GlobalMetadataHeader_ptr) {
        LOGI("Found s_GlobalMetadata and s_GlobalMetadataHeader pointers.");

        void* metadata = *(void**)s_GlobalMetadata_ptr;
        auto header = (Il2CppGlobalMetadataHeader*)s_GlobalMetadataHeader_ptr;

        // Более точный способ расчета размера метаданных
        size_t metadata_size = 0;
        if (header->sanity == 0xFAB11BAF) { // Проверка "магического" числа
            // В новых версиях Unity размер можно посчитать так:
            metadata_size = header->exportedTypeDefinitionsOffset + (header->exportedTypeDefinitionsCount * sizeof(int32_t));
        } else {
            LOGE("Metadata sanity check failed!");
        }

        LOGI("Calculated metadata size: %zu bytes", metadata_size);

        if (metadata && metadata_size > 0) {
            std::string out_path(g_game_data_dir);
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
    } else {
        LOGE("Could not find s_GlobalMetadata or s_GlobalMetadataHeader symbols.");
    }

    // После дампа метаданных, запускаем дамп адресов
    il2cpp_dump(g_game_data_dir);

    return result;
}

void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_handle: %p", handle);

#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}
#include "il2cpp-api-functions.h"
#undef DO_API

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

    // Ставим хук на il2cpp_init
    if (il2cpp_init) {
        LOGI("Hooking il2cpp_init at %p", il2cpp_init);
        DobbyHook(
                (void*)il2cpp_init,
                (dobby_dummy_func_t)hook_il2cpp_init,
                (dobby_dummy_func_t*)&orig_il2cpp_init
        );
    } else {
        LOGE("il2cpp_init not found, cannot hook for metadata decryption.");
    }
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
                auto RVA = (uint64_t) method->methodPointer - il2cpp_base;
                auto offset = (uint64_t) method->methodPointer;
                out << "\t";
                auto ret_type_name = il2cpp_type_get_name(il2cpp_method_get_return_type(method));
                out << ret_type_name << " " << method_name << "()";
                free(ret_type_name);
                out << "; // RVA: 0x" << std::hex << RVA << " Offset: 0x" << offset << std::dec << std::endl;
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

// Эта функция теперь будет вызываться из hack.cpp
void start_dump_process(const char* game_data_dir) {
    g_game_data_dir = game_data_dir; // Сохраняем путь для использования в хуке
    // Просто инициализируем API. Дальнейший дамп произойдет внутри хука.
    bool load = false;
    for (int i = 0; i < 10; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            il2cpp_api_init(handle);
            // Больше ничего не делаем здесь, ждем вызова il2cpp_init игрой
            break;
        } else {
            sleep(1);
        }
    }
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}