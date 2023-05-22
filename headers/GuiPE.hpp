#ifndef HEADERS_PEFILE_HPP
#define HEADERS_PEFILE_HPP

#include <iostream>
#include <fstream>
#include <sstream>

#include "Win32.hpp"
#include "QTableWidget"
#include "QTableWidgetItem"
#include "QVBoxLayout"
#include "QHeaderView"
#include "QLabel"

class GuiPE
{
    private:
        std::ifstream file;

        QTabWidget * PETabs;

        QTableWidget * DosTable;
        QTableWidget * FileHeaderTable;
        QTableWidget * OptionalHeaderTable;
        QTableWidget * SectionHeaderTable;
        QTableWidget * ImportsTable;
        QTableWidget * ImportEntriesTable;
        QTableWidget * ExceptionsTable;
        QTableWidget * BaseRelocationTable;
        QTableWidget * TlsTable;
        QTableWidget * TlsCallbackTable;

        DOS_HEADER dos_header;
        NTHeader_64 nt_header64;
        SECTION_HEADER section_header;
        IMPORT_DESCRIPTOR import_descriptor;
        IMPORT_DESCRIPTOR * import_table;
        IMPORT_BY_NAME import_name;
        ILT_ENTRY ilt_entry;
        EXCEPTIONS exceptions;
        BASE_RELOCATION base_relocation;
        BASE_RELOCATION_ENTRY base_relocation_entry;
        TLS_DIRECTORY64 tls_directory64;
        TLS_CALLBACK64 tls_callback64;

        void GUIDosHeader();
        void GUINtHeader();
        void GUISections();
        void GUIImports();
        void GUIExceptions();
        void GUIBaseRelocations();
        void GUITLS();

        static void formatTable(QTableWidget * table);
        unsigned int RvaToOffset(unsigned int rva);

    public:
        void Load(const std::string &path);
        QTabWidget * getTabs();

};

#endif //HEADERS_PEFILE_HPP
