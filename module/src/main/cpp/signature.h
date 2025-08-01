#ifndef ZYGISK_IL2CPPDUMPER_SIGNATURE_H
#define ZYGISK_IL2CPPDUMPER_SIGNATURE_H

#include <cstdint>
#include <vector>

// Находит адрес по сигнатуре (последовательности байт) в указанном диапазоне памяти.
// Паттерн может содержать '?' в качестве wildcard.
uintptr_t find_signature(uintptr_t start, uintptr_t end, const char* pattern);

// Находит сигнатуру для пары инструкций ADRP+LDR/ADD и вычисляет из них целевой адрес.
// Это специфично для архитектуры ARM64.
uintptr_t find_and_resolve_signature(uintptr_t start, uintptr_t end, const char* pattern);

#endif //ZYGISK_IL2CPPDUMPER_SIGNATURE_H