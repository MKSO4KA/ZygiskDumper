//
// Created by Perfare on 2020/7/4.
//

#ifndef ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H
#define ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H

void il2cpp_api_init(void *handle);

void il2cpp_dump(const char *outDir);

void start_dump_process(const char *game_data_dir);


#endif //ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H