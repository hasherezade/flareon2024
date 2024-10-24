#pragma once
#include <windows.h>
#include <iostream>

inline bool save_to_file(const char* path, BYTE* buf, size_t buf_size)
{
    FILE* fp = nullptr;
    fopen_s(&fp, path, "wb");
    if (!fp) return false;

    fwrite(buf, 1, buf_size, fp);
    fclose(fp);
    return true;
}

inline BYTE* read_file(const char* path, size_t& buf_size)
{
    FILE* fp = nullptr;
    fopen_s(&fp, path, "rb");
    if (!fp) return nullptr;

    fseek(fp, 0, SEEK_END);
    size_t fsize = ftell(fp);
    if (!fsize) {
        fclose(fp);
        return nullptr;
    }
    fseek(fp, 0, SEEK_SET);
    BYTE* buf = (BYTE*)::calloc(fsize, 1);
    if (buf) {
        buf_size = fsize;
        fread(buf, 1, fsize, fp);
    }
    fclose(fp);
    return buf;
}