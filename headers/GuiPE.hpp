#ifndef HEADERS_PEFILE_HPP
#define HEADERS_PEFILE_HPP

#include <iostream>
#include <fstream>
#include <algorithm>

#include "Win32.hpp"

#include "QTableWidget"
#include "QTableWidgetItem"
#include "QVBoxLayout"
#include "QHeaderView"
#include "QLabel"
#include "QSplitter"

class GuiPE : public QObject
{
   Q_OBJECT

    private:
        std::ifstream file;

        QTabWidget * PETabs;

        QTableWidget * hexViewer = nullptr;
        QTableWidget * DosTable;
        QTableWidget * FileHeaderTable;
        QTableWidget * OptionalHeaderTable;
        QTableWidget * SectionHeaderTable;
        QTableWidget * ImportsTable;
        QTableWidget * ImportEntriesTable;
        QTableWidget * ExceptionsTable;
        QTableWidget * BaseRelocationTable;
        QTableWidget * BaseRelocationEntriesTable;
        QTableWidget * TlsTable;
        QTableWidget * TlsCallbackTable;

        QLabel * baseRelocationCountLabel;
        QLabel * importsCountLabel;

        DOS_HEADER dos_header;
        NTHeader_64 nt_header64;
        SECTION_HEADER section_header;
        IMPORT_DESCRIPTOR import_descriptor;
        IMPORT_DESCRIPTOR * import_table;
        IMPORT_BY_NAME import_name;
        ILT_ENTRY ilt_entry;
        EXCEPTIONS exceptions;
        BASE_RELOCATION base_relocation;
        BASE_RELOCATION * base_relocation_table;
        BASE_RELOCATION_ENTRY base_relocation_entry;
        TLS_DIRECTORY64 tls_directory64;
        TLS_CALLBACK64 tls_callback64;

        int entry_counter;
        int import_directory_count;
        int base_relocation_directory_count;

        void GUIDosHeader();
        void GUINtHeader();
        void GUISections();
        void GUIImports();
        void GUIExceptions();
        void GUIBaseRelocations();
        void GUITLS();

        static void formatTable(QTableWidget * table);
        unsigned int RvaToOffset(unsigned int rva);

        void connectTablesToHexViewer() const;
        void onOffsetCellClicked(int row, int column);
        void updateHexViewer(int offset);
        void handleImportSelection();
        void handleBaseRelocationSelection();
    public:
        void Load(const std::string &path);
        void createHexByteViewer(QWidget * parent, const std::string& filePath, int numLines, int offset);

        QTabWidget * getTabs();
};

#endif //HEADERS_PEFILE_HPP
