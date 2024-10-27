#pragma once
#include "pin.H"

#include <iostream>
#include <fstream>

#define DELIMITER ';'

class TraceLog {

protected:

    bool _createFile(std::ofstream& file, const std::string& fileName)
    {
        if (file.is_open()) {
            return true;
        }
        file.open(fileName.c_str());
        if (file.is_open()) {
            return true;
        }
        return false;
    }

    std::string m_traceFileName;
    std::string m_listingFileName;
    std::ofstream m_traceFile;
    std::ofstream m_ListingFile;

public:
    void init(std::string fileName)
    {
        m_traceFileName = fileName + ".tag";
        m_listingFileName = fileName + ".listing.txt";
        _createFile(m_traceFile, m_traceFileName);
        _createFile(m_ListingFile, m_listingFileName);
    }

    void TraceLog::logLine(const std::string& str)
    {
        if (!_createFile(m_traceFile, m_traceFileName)) return;

        m_traceFile
            << str
            << std::endl;
        m_traceFile.flush();
    }

    void TraceLog::logListingLine(const std::string& str)
    {
        if (!_createFile(m_ListingFile, m_listingFileName)) return;

        m_ListingFile
            << str
            << std::endl;
        m_ListingFile.flush();
    }

    void TraceLog::logInstruction(const ADDRINT base, const ADDRINT rva, const std::string& mnem)
    {
        if (!_createFile(m_traceFile, m_traceFileName)) return;
        m_traceFile
            << std::hex << rva
            << DELIMITER
            << mnem
            << std::endl;
        m_traceFile.flush();
    }

};