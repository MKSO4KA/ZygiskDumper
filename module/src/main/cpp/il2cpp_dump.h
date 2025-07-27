//
// Created by Perfare on 2020/7/4.
//

#ifndef ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H
#define ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H

void il2cpp_api_init(void *handle);

void il2cpp_dump(const char *outDir);

// ИЗМЕНЕННАЯ СТРОКА: Объявляем нашу новую функцию-сканер
bool find_and_dump_metadata(const char *outDir, int scan_id);

#endif //ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H