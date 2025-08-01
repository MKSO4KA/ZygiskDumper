// module/src/main/cpp/il2cpp_dump.h

#ifndef ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H
#define ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H

void il2cpp_api_init(void *handle);

// Эта функция останется для дампа адресов, но будет вызываться из хука
void il2cpp_dump(const char *outDir);

// Новая функция, которая будет запускать весь процесс
void start_dump_process(const char *game_data_dir);

#endif //ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H