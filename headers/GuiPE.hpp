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

class GuiPE
{
    private:
        std::ifstream file;

        QTabWidget * PETabs;

        QTableWidget * DosTable;
        QTableWidget * FileHeaderTable;
        QTableWidget * OptionalHeaderTable;
        QTableWidget * SectionHeaderTable;
        QTableWidget * Imports;
        QTableWidget * ImportEntries;

        DOS_HEADER dos_header;
        NTHeader_64 nt_header64;
        SECTION_HEADER section_header;
        IMPORT_DESCRIPTOR import_descriptor;
        IMPORT_DESCRIPTOR * import_table;
        IMPORT_BY_NAME import_name;
        ILT_ENTRY ilt_entry;

        void GUIDosHeader();
        void GUINtHeader();
        void GUISections();
        void GUIImports();

        static void formatTable(QTableWidget * table);
        unsigned int RvaToOffset(unsigned int rva);
        void EntryNameClicked(QTableWidgetItem * item);

    public:
        void Load(const std::string &path);
        QTabWidget * getTabs();

};

#endif //HEADERS_PEFILE_HPP
