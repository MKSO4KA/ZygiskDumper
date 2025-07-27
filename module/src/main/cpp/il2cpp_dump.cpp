//
// Created by Perfare on 2020/7/4.
//

// ИСПРАВЛЕНИЕ 1: Подключаем dobby.h в первую очередь, чтобы типы RegisterContext и HookEntryInfo были известны.
#include "include/dobby.h"

#include "il2cpp_dump.h"
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
static std::map<void*, int> g_call_counts;
static std::mutex g_mutex;
static std::ofstream g_log_stream;

// --- УНИВЕРСАЛЬНЫЙ ОБРАБОТЧИК ВЫЗОВОВ ---
void generic_pre_handler(RegisterContext *ctx, const HookEntryInfo *info) {
    // ИСПРАВЛЕНИЕ 3: Более правильное использование lock_guard
    std::lock_guard<std::mutex> lock(g_mutex);

    void* method_ptr = (void*)info->function_address;
    int& count = g_call_counts[method_ptr];
    count++;

    // Ограничим логирование, чтобы не засорять лог слишком сильно
    if (count > 5) {
        return;
    }

    const MethodInfo* methodInfo = (const MethodInfo*)info->user_data;
    if (!methodInfo) return;

    const char* method_name = il2cpp_method_get_name(methodInfo);
    Il2CppClass* klass = il2cpp_method_get_declaring_type(methodInfo);
    const char* class_name = il2cpp_class_get_name(klass);

    std::stringstream ss;
    ss << "[CALL #" << count << " PRE] " << class_name << "::" << method_name << " (at " << method_ptr << ")\n";
    ss << "  Args: ";

    // ИСПРАВЛЕНИЕ 2: Код для логирования регистров, работающий на разных архитектурах
#if defined(__aarch64__) // arm64-v8a
    for (int i = 0; i < 8; ++i) {
        ss << "x" << i << "=0x" << std::hex << ctx->general.regs.x[i] << " ";
    }
#elif defined(__arm__) // armeabi-v7a
    for (int i = 0; i < 8; ++i) {
        ss << "r" << i << "=0x" << std::hex << ctx->general.regs.r[i] << " ";
    }
#elif defined(__x86_64__) // x86_64
    ss << "rdi=0x" << std::hex << ctx->general.rdi << " ";
    ss << "rsi=0x" << std::hex << ctx->general.rsi << " ";
    ss << "rdx=0x" << std::hex << ctx->general.rdx << " ";
    ss << "rcx=0x" << std::hex << ctx->general.rcx << " ";
#elif defined(__i386__) // x86
    // Для x86 аргументы передаются через стек, здесь для примера показаны только общие регистры
    ss << "eax=0x" << std::hex << ctx->general.eax << " ";
    ss << "ebx=0x" << std::hex << ctx->general.ebx << " ";
    ss << "ecx=0x" << std::hex << ctx->general.ecx << " ";
    ss << "edx=0x" << std::hex << ctx->general.edx << " ";
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
    // В Zygisk/Riru модуль загружается до инициализации il2cpp, поэтому эта проверка может быть не нужна
    // или должна быть выполнена в другом месте. Но оставим ее на всякий случай.
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
                    // Передаем method в user_data, чтобы получить информацию о нем в хендлере
                    DobbyInstrument((void *)method->methodPointer, generic_pre_handler, (void*)method);
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