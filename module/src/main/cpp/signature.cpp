#include "signature.h"
#include <string>
#include <vector>
#include <cctype>

// Вспомогательная функция для преобразования одного hex-символа в число
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1; // Некорректный символ
}

// Преобразует строку с паттерном (например, "48 89 ?? 57") в вектор байт.
// Эта версия более безопасна и не использует const_cast.
std::vector<char> pattern_to_bytes(const char* pattern) {
    std::vector<char> bytes;
    const char* p = pattern;
    while (*p) {
        // Пропускаем пробелы
        if (isspace(*p)) {
            p++;
            continue;
        }

        // Обрабатываем wildcard '?'
        if (*p == '?') {
            bytes.push_back('?');
            p++;
            // Пропускаем второй '?' если он есть (например, "??")
            if (*p == '?') {
                p++;
            }
            continue;
        }

        // Обрабатываем пару hex-символов
        if (isxdigit(*p) && isxdigit(*(p + 1))) {
            int val1 = hex_char_to_int(*p);
            int val2 = hex_char_to_int(*(p + 1));
            bytes.push_back(static_cast<char>((val1 << 4) | val2));
            p += 2;
        } else {
            // Если формат нарушен, просто пропускаем символ, чтобы избежать бесконечного цикла
            p++;
        }
    }
    return bytes;
}


// Вспомогательная функция для сравнения участка памяти с паттерном.
bool compare(const uint8_t* data, const std::vector<char>& pattern) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] != '?' && data[i] != static_cast<uint8_t>(pattern[i])) {
            return false;
        }
    }
    return true;
}

uintptr_t find_signature(uintptr_t start, uintptr_t end, const char* pattern) {
    std::vector<char> pattern_bytes = pattern_to_bytes(pattern);
    if (pattern_bytes.empty()) {
        return 0;
    }
    size_t pattern_size = pattern_bytes.size();

    // Убедимся, что не выйдем за пределы памяти
    if (start > end - pattern_size) {
        return 0;
    }

    for (uintptr_t p = start; p <= end - pattern_size; ++p) {
        if (compare(reinterpret_cast<const uint8_t*>(p), pattern_bytes)) {
            return p;
        }
    }
    return 0;
}

// Декодирует пару инструкций ADRP + LDR/ADD для архитектуры ARM64.
uintptr_t resolve_adrp_ldr(uintptr_t adrp_addr) {
    // Декодируем инструкцию ADRP
    uint32_t adrp_instr = *reinterpret_cast<uint32_t*>(adrp_addr);
    int64_t imm = static_cast<int64_t>(((adrp_instr >> 3) & 0x1FFFFC) | ((adrp_instr >> 29) & 0x3));
    // Расширение знака для 21-битного смещения
    if (imm & (1LL << 20)) {
        imm |= ~((1LL << 21) - 1);
    }
    uintptr_t page_addr = (adrp_addr & ~0xFFFULL) + (imm << 12);

    // Декодируем следующую инструкцию (LDR или ADD)
    uint32_t next_instr = *reinterpret_cast<uint32_t*>(adrp_addr + 4);

    // Проверяем, это LDR (Unsigned offset)
    // F9400000 - это маска для LDR Xd, [Xn, #pimm]
    if ((next_instr & 0xFFC00000) == 0xF9400000) {
        uint32_t imm12 = (next_instr >> 10) & 0xFFF;
        // Для 64-битных указателей (X-регистры) смещение умножается на 8
        return page_addr + (imm12 * 8);
    }
    // Проверяем, это ADD
    // 91000000 - это маска для ADD Xd, Xn, #imm
    if ((next_instr & 0xFF800000) == 0x91000000) {
        uint32_t imm12 = (next_instr >> 10) & 0xFFF;
        return page_addr + imm12;
    }

    return 0; // Неизвестная или неподдерживаемая инструкция после ADRP
}

uintptr_t find_and_resolve_signature(uintptr_t start, uintptr_t end, const char* pattern) {
    uintptr_t adrp_addr = find_signature(start, end, pattern);
    if (adrp_addr == 0) {
        return 0;
    }
    return resolve_adrp_ldr(adrp_addr);
}