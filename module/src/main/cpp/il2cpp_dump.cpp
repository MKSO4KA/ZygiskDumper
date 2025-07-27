// module/src/main/cpp/il2cpp_dump.cpp

#include "il2cpp_dump.h"
#include "include/dobby.h" // <-- ВКЛЮЧАЕМ DOBBY ЗДЕСЬ
#include <dlfcn.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <map>
#include <mutex>
#include <cinttypes>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

#define DO_API(r, n, p) r (*n) p
#include "il2cpp-api-functions.h"
#undef DO_API

// --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ ПРОСЛУШКИ ---
static std::map<void*, const MethodInfo*> g_method_map; // Карта для связи адреса с MethodInfo
static std::map<void*, int> g_call_counts;
static std::mutex g_mutex;
static std::ofstream g_log_stream;

// --- ИСПРАВЛЕННЫЙ УНИВЕРСАЛЬНЫЙ ОБРАБОТЧИК ВЫЗОВОВ ---
// Сигнатура изменена в соответствии с dobby.h
void generic_pre_handler(void *address, DobbyRegisterContext *ctx) {
    std::lock_guard<std::mutex> lock(g_mutex);

    // Получаем MethodInfo из нашей глобальной карты
    const MethodInfo* methodInfo = nullptr;
    auto it = g_method_map.find(address);
    if (it != g_method_map.end()) {
        methodInfo = it->second;
    }

    if (!methodInfo) return; // Если не нашли, ничего не делаем

    int& count = g_call_counts[address];
    count++;

    // Ограничим логирование, чтобы не засорять лог слишком сильно
    if (count > 5) {
        return;
    }

    const char* method_name = il2cpp_method_get_name(methodInfo);
    Il2CppClass* klass = il2cpp_method_get_declaring_type(methodInfo);
    const char* class_name = il2cpp_class_get_name(klass);

    std::stringstream ss;
    ss << "[CALL #" << count << " PRE] " << class_name << "::" << method_name << " (at " << address << ")\n";
    ss << "  Args: ";

    // Код для логирования регистров, работающий на разных архитектурах
#if defined(__aarch64__) // arm64-v8a
    for (int i = 0; i < 8; ++i) {
        // ИСПРАВЛЕНИЕ 1: Убираем .regs
        ss << "x" << i << "=0x" << std::hex << ctx->general.x[i] << " ";
    }
#elif defined(__arm__) // armeabi-v7a
    for (int i = 0; i < 8; ++i) {
        // ИСПРАВЛЕНИЕ 2: Убираем .regs
        ss << "r" << i << "=0x" << std::hex << ctx->general.r[i] << " ";
    }
#elif defined(__x86_64__) // x86_64
    ss << "rdi=0x" << std::hex << ctx->general.regs.rdi << " ";
    ss << "rsi=0x" << std::hex << ctx->general.regs.rsi << " ";
    ss << "rdx=0x" << std::hex << ctx->general.regs.rdx << " ";
    ss << "rcx=0x" << std::hex << ctx->general.regs.rcx << " ";
#elif defined(__i386__) // x86
    // Для x86 аргументы передаются через стек, здесь для примера показаны только общие регистры
    ss << "eax=0x" << std::hex << ctx->general.regs.eax << " ";
    ss << "ebx=0x" << std::hex << ctx->general.regs.ebx << " ";
    ss << "ecx=0x" << std::hex << ctx->general.regs.ecx << " ";
    ss << "edx=0x" << std::hex << ctx->general.regs.edx << " ";
#endif
    ss << "\n";

    LOGI("%s", ss.str().c_str());
    if (g_log_stream.is_open()) {
        g_log_stream << ss.str() << std::flush;
    }
}

static uint64_t il2cpp_base = 0;

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
    int retries = 0;
    while (!il2cpp_is_vm_thread(nullptr) && retries < 10) {
        LOGI("Waiting for il2cpp_init... (%d/10)", retries + 1);
        sleep(1);
        retries++;
    }
    auto domain = il2cpp_domain_get();
    if (domain) {
        il2cpp_thread_attach(domain);
    } else {
        LOGE("Failed to get il2cpp domain.");
    }
}

void il2cpp_dump(const char *outDir) {
    LOGI("--- TOTAL SURVEILLANCE MODE ---");

    auto logPath = std::string(outDir).append("/trace.txt");
    g_log_stream.open(logPath, std::ios::out | std::ios::app);
    if (g_log_stream.is_open()) {
        LOGI("Trace log will be saved to: %s", logPath.c_str());
    } else {
        LOGE("Failed to open trace log file: %s", logPath.c_str());
    }

    size_t size;
    auto domain = il2cpp_domain_get();
    if (!domain) {
        LOGE("il2cpp_dump failed: domain is null.");
        return;
    }
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);

    int hooked_count = 0;
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;
        auto classCount = il2cpp_image_get_class_count(image);
        for (int j = 0; j < classCount; ++j) {
            auto klass = const_cast<Il2CppClass *>(il2cpp_image_get_class(image, j));
            if (!klass) continue;
            void *iter = nullptr;
            while (auto method = il2cpp_class_get_methods(klass, &iter)) {
                if (method->methodPointer) {
                    void* method_ptr = (void*)method->methodPointer;
                    // Сохраняем метод в карту
                    g_method_map[method_ptr] = method;
                    // Вызываем DobbyInstrument с правильной сигнатурой
                    DobbyInstrument(method_ptr, generic_pre_handler);
                    hooked_count++;
                }
            }
        }
    }

    LOGI("--- Hooking finished. Hooked %d methods. Game will be slow. ---", hooked_count);
    if (g_log_stream.is_open()) {
        g_log_stream << "--- Hooking finished. Hooked " << hooked_count << " methods. ---\n\n" << std::flush;
    }
}