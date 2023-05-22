#include <iostream>
#include <bit>
#include <vector>
#include <string>

QTabWidget * GuiPE::getTabs()
{
    return PETabs;
}

void GuiPE::formatTable(QTableWidget * table)
{
    table->setColumnWidth(0, 400);

    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionsClickable(false);
    table->verticalHeader()->setSectionsClickable(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);

    table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionMode(QAbstractItemView::NoSelection);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);

    for(int i = 1; i < table->horizontalHeader()->count(); i++)
    {
        table->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
    }
}

unsigned int GuiPE::RvaToOffset(unsigned int rva) {
    for(int i = 0; i < nt_header64.file_header.NumberOfSections; i++) {
        unsigned int offset = (dos_header.e_lfanew + sizeof(nt_header64)) + (i * sizeof(section_header));
        file.seekg(offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&section_header),
                sizeof(section_header)
        );

        if(rva >= section_header.VirtualAddress && rva < (section_header.VirtualAddress + section_header.Misc.VirtualSize)) {
            return (rva - section_header.VirtualAddress) + section_header.PointerToRawData;
        }
    }
    return 0;
}


void GuiPE::GUITLS()
{
    auto * TlsLayout = new QVBoxLayout();

    formatTable(TlsTable);

    QStringList TlsHeaders;
    TlsHeaders << "Offset" << "Name" << "Value";
    TlsTable->setHorizontalHeaderLabels(TlsHeaders);

    DWORD directory_tls_rva = nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_TLS].VirtualAddress;
    int tls_entry_counter = 0;
    unsigned int offset = RvaToOffset(directory_tls_rva);

    file.seekg(offset, std::ios::beg);
    file.read(
            std::bit_cast<char*>(&tls_directory64),
            sizeof(tls_directory64)
    );

    TlsTable->setItem(0, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
    TlsTable->setItem(0, 1, new QTableWidgetItem("StartAddressOfRawData"));
    TlsTable->setItem(0, 2, new QTableWidgetItem(QString::number(tls_directory64.StartAddressOfRawData, 16).toUpper()));

    offset += sizeof(tls_directory64.StartAddressOfRawData);
    TlsTable->setItem(1, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
    TlsTable->setItem(1, 1, new QTableWidgetItem("EndAddressOfRawData"));
    TlsTable->setItem(1, 2, new QTableWidgetItem(QString::number(tls_directory64.EndAddressOfRawData, 16).toUpper()));

    offset += sizeof(tls_directory64.EndAddressOfRawData);
    TlsTable->setItem(2, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
    TlsTable->setItem(2, 1, new QTableWidgetItem("AddressOfIndex"));
    TlsTable->setItem(2, 2, new QTableWidgetItem(QString::number(tls_directory64.AddressOfIndex, 16).toUpper()));

    offset += sizeof(tls_directory64.AddressOfIndex);
    TlsTable->setItem(3, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
    TlsTable->setItem(3, 1, new QTableWidgetItem("AddressOfCallBacks"));
    TlsTable->setItem(3, 2, new QTableWidgetItem(QString::number(tls_directory64.AddressOfCallBacks, 16).toUpper()));

    offset += sizeof(tls_directory64.AddressOfCallBacks);
    TlsTable->setItem(4, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
    TlsTable->setItem(4, 1, new QTableWidgetItem("SizeOfZeroFill"));
    TlsTable->setItem(4, 2, new QTableWidgetItem(QString::number(tls_directory64.SizeOfZeroFill, 16).toUpper()));

    offset += sizeof(tls_directory64.SizeOfZeroFill);
    TlsTable->setItem(5, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
    TlsTable->setItem(5, 1, new QTableWidgetItem("Characteristics"));
    TlsTable->setItem(5, 2, new QTableWidgetItem(QString::number(tls_directory64.Characteristics, 16).toUpper()));

    formatTable(TlsCallbackTable);

    QStringList TlsCallbackHeaders;
    TlsCallbackHeaders << "Offset" << "Callback";
    TlsCallbackTable->setHorizontalHeaderLabels(TlsCallbackHeaders);

    while(true) {
        unsigned int callback_offset = (tls_entry_counter * sizeof(tls_callback64)) + RvaToOffset(tls_directory64.AddressOfCallBacks - nt_header64.optional_header64.ImageBase);
        std::cout << std::hex << callback_offset << "\n";
        file.seekg(callback_offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&tls_callback64),
                sizeof(tls_callback64)
        );

        if(tls_callback64.Callback == 0) {
            break;
        }
        TlsCallbackTable->insertRow(tls_entry_counter);
        TlsCallbackTable->setItem(tls_entry_counter, 0, new QTableWidgetItem(QString::number(callback_offset, 16).toUpper()));
        TlsCallbackTable->setItem(tls_entry_counter, 1, new QTableWidgetItem(QString::number(tls_callback64.Callback, 16).toUpper()));
        tls_entry_counter++;
    }

    auto * labelFrame = new QFrame();
    labelFrame->setFrameStyle(QFrame::Box);
    labelFrame->setStyleSheet("background-color: lightgrey;");

    auto * callbackLabel = new QLabel();
    callbackLabel->setText("TLS Callbacks [" + QString::number(tls_entry_counter) + " entries]");

    auto * labelLayout = new QHBoxLayout(labelFrame);
    labelLayout->addWidget(callbackLabel);
    labelLayout->setContentsMargins(5, 5, 5, 5);

    TlsLayout->addWidget(TlsTable);
    TlsLayout->addWidget(labelFrame);
    TlsLayout->addWidget(TlsCallbackTable);

    auto * tlsWidget = new QWidget();
    tlsWidget->setLayout(TlsLayout);

    PETabs->addTab(tlsWidget, QIcon(R"(C:\Users\FindW\Desktop\folder_icon.jpg)"), "TLS");
}

void GuiPE::GUIBaseRelocations()
{
    formatTable(BaseRelocationTable);

    QStringList headers;
    headers << "Offset" << "Page RVA" << "Block Size" << "Entries Count";
    BaseRelocationTable->setHorizontalHeaderLabels(headers);

    DWORD directory_base_relocation_rva = nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    int base_relocation_directory_count = 0;
    int base_relocation_size_counter = 0;

    while(true) {
        unsigned int offset = base_relocation_size_counter + RvaToOffset(directory_base_relocation_rva);
        file.seekg(offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&base_relocation),
                sizeof(base_relocation)
        );

        if(base_relocation.VirtualAddress == 0x00000000 && base_relocation.SizeOfBlock == 0x00000000) {
            break;
        }

        base_relocation_directory_count++;
        base_relocation_size_counter += (int) base_relocation.SizeOfBlock;
    }

    BaseRelocationTable->setRowCount(base_relocation_directory_count);

    auto base_relocation_table = new BASE_RELOCATION[base_relocation_directory_count];
    base_relocation_size_counter = 0;

    for(int i = 0; i < base_relocation_directory_count; i++) {
        unsigned int offset = base_relocation_size_counter + RvaToOffset(directory_base_relocation_rva);

        file.seekg(offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&base_relocation_table[i]),
                sizeof(base_relocation)
        );
        BaseRelocationTable->setItem(i, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
        base_relocation_size_counter += (int) base_relocation_table[i].SizeOfBlock;
    }

    for(int i = 0; i < base_relocation_directory_count; i++) {
        unsigned int entries = (base_relocation_table[i].SizeOfBlock - sizeof(base_relocation)) / sizeof(WORD);

        BaseRelocationTable->setItem(i, 1, new QTableWidgetItem(QString::number(base_relocation_table[i].VirtualAddress, 16).toUpper()));
        BaseRelocationTable->setItem(i, 2, new QTableWidgetItem(QString::number(base_relocation_table[i].SizeOfBlock, 16).toUpper()));
        BaseRelocationTable->setItem(i, 3, new QTableWidgetItem(QString::number(entries, 16).toUpper()));
    }

    PETabs->addTab(BaseRelocationTable, QIcon(R"(C:\Users\FindW\Desktop\folder_icon.jpg)"), "Base Reloc.");
}

void GuiPE::GUIExceptions()
{
    formatTable(ExceptionsTable);

    QStringList headers;
    headers << "Offset" << "BeginAddress" << "EndAddress" << "UnwindInfoAddress";
    ExceptionsTable->setHorizontalHeaderLabels(headers);

    DWORD directory_exception_rva = nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    int exception_directory_count = 0;

    while(true) {
        unsigned int offset = (exception_directory_count * sizeof(EXCEPTIONS)) + RvaToOffset(directory_exception_rva);

        file.seekg(offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&exceptions),
                sizeof(exceptions)
        );

        if(exceptions.BeginAddress == 0 && exceptions.EndAddress == 0 && exceptions.UnwindInfoAddress == 0) {
            break;
        }

        ExceptionsTable->insertRow(exception_directory_count);
        ExceptionsTable->setItem(exception_directory_count, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
        ExceptionsTable->setItem(exception_directory_count, 1, new QTableWidgetItem(QString::number(exceptions.BeginAddress, 16).toUpper()));
        ExceptionsTable->setItem(exception_directory_count, 2, new QTableWidgetItem(QString::number(exceptions.EndAddress, 16).toUpper()));
        ExceptionsTable->setItem(exception_directory_count, 3, new QTableWidgetItem(QString::number(exceptions.UnwindInfoAddress, 16).toUpper()));

        exception_directory_count++;
    }
    PETabs->addTab(ExceptionsTable, QIcon(R"(C:\Users\FindW\Desktop\folder_icon.jpg)"), "Exceptions");
}

void GuiPE::GUIImports()
{
    formatTable(ImportsTable);

    QStringList headers;
    headers << "Offset" << "Name" << "Bound?" << "OriginalFirstThunk" << "TimeDateStamp" << "Forwarder"
            << "Name RVA" << "FirstThunk";
    ImportsTable->setHorizontalHeaderLabels(headers);

    DWORD directory_import_rva = nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    int import_directory_count = 0;

    while(true) {
        unsigned int offset = (import_directory_count * sizeof(IMPORT_DESCRIPTOR)) + RvaToOffset(directory_import_rva);
        file.seekg(offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&import_descriptor),
                sizeof(import_descriptor)
        );

        if(import_descriptor.Name == 0x00000000 && import_descriptor.FirstThunk == 0x00000000) {
            break;
        }
        import_directory_count++;
    }

    import_table = new IMPORT_DESCRIPTOR[import_directory_count];
    for(int i = 0; i < import_directory_count; i++) {
        unsigned int offset = (i * sizeof(import_descriptor)) + RvaToOffset(directory_import_rva);
        file.seekg(offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&import_table[i]),
                sizeof(import_descriptor)
        );
        ImportsTable->setItem(i, 0, new QTableWidgetItem(QString::number(offset, 16).toUpper()));
    }

    ImportsTable->setRowCount(import_directory_count);
    for(int i = 0; i < import_directory_count; i++) {
        unsigned int name_address = RvaToOffset(import_table[i].Name);
        unsigned int name_size = 0;

        while (true) {
            char temp;
            file.seekg((name_address + name_size), std::ios::beg);
            file.read(
                    &temp,
                    sizeof(char)
            );

            if (temp == 0x00) {
                break;
            }
            name_size++;
        }

        char *name = new char[name_size + 2];
        file.seekg(name_address, std::ios::beg);
        file.read(
                name,
                (unsigned int) (name_size * sizeof(char) + 1)
        );

        QString bound;
        if (import_table[i].TimeDateStamp == 0) {

            bound = "FALSE";
        } else {
            bound = "TRUE";
        }

        ImportsTable->setItem(i, 1, new QTableWidgetItem(QString(name)));
        ImportsTable->setItem(i, 2, new QTableWidgetItem(QString(bound)));
        ImportsTable->setItem(i, 3, new QTableWidgetItem(QString::number(import_table[i].misc.OriginalFirstThunk, 16).toUpper()));
        ImportsTable->setItem(i, 4, new QTableWidgetItem(QString::number(import_table[i].TimeDateStamp, 16).toUpper()));
        ImportsTable->setItem(i, 5, new QTableWidgetItem(QString::number(import_table[i].ForwarderChain, 16).toUpper()));
        ImportsTable->setItem(i, 6, new QTableWidgetItem(QString::number(import_table[i].Name, 16).toUpper()));
        ImportsTable->setItem(i, 7, new QTableWidgetItem(QString::number(import_table[i].FirstThunk, 16).toUpper()));

        delete[] name;
    }
    PETabs->addTab(ImportsTable, QIcon(R"(C:\Users\FindW\Desktop\folder_icon.jpg)"), "Imports");
}

void GuiPE::GUISections()
{
    formatTable(SectionHeaderTable);

    QStringList headers;
    headers << "Name" << "Raw Address" << "Raw Size" << "Virtual Address" << "Virtual Size" << "Characteristics"
    << "Ptr to Reloc." << "Ptr to Line Num." << "Num. of Reloc." << "Num. of Linenum.";
    SectionHeaderTable->setHorizontalHeaderLabels(headers);

    file.seekg((unsigned) (dos_header.e_lfanew + sizeof(nt_header64)));
    file.read(
            std::bit_cast<char*>(&section_header),
            sizeof(section_header)
    );

    SectionHeaderTable->setRowCount(nt_header64.file_header.NumberOfSections);
    for(int i = 0; i < nt_header64.file_header.NumberOfSections; i++) {
        unsigned int offset = (dos_header.e_lfanew + sizeof(nt_header64)) + (i * sizeof(section_header));
        file.seekg(offset, std::ios::beg);
        file.read(
                std::bit_cast<char*>(&section_header),
                sizeof(section_header)
        );

        char name[9];
        std::memcpy(name, section_header.Name, 8);
        QString nameQ(name);

        SectionHeaderTable->setItem(0 + i, 0, new QTableWidgetItem(QString(nameQ)));
        SectionHeaderTable->setItem(0 + i, 1, new QTableWidgetItem(QString::number(section_header.PointerToRawData, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 2, new QTableWidgetItem(QString::number(section_header.SizeOfRawData, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 3, new QTableWidgetItem(QString::number(section_header.VirtualAddress, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 4, new QTableWidgetItem(QString::number(section_header.Misc.VirtualSize, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 5, new QTableWidgetItem(QString::number(section_header.Characteristics, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 6, new QTableWidgetItem(QString::number(section_header.PointerToRelocations, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 7, new QTableWidgetItem(QString::number(section_header.PointerToLinenumbers, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 8, new QTableWidgetItem(QString::number(section_header.NumberOfRelocations, 16).toUpper()));
        SectionHeaderTable->setItem(0 + i, 9, new QTableWidgetItem(QString::number(section_header.NumberOfLinenumbers, 16).toUpper()));
    }
    PETabs->addTab(SectionHeaderTable, "Section Headers");
}

void GuiPE::GUINtHeader()
{
    file.seekg(dos_header.e_lfanew);
    file.read(
            std::bit_cast<char*>(&nt_header64),
            sizeof(nt_header64)
    );

    formatTable(FileHeaderTable);
    formatTable(OptionalHeaderTable);

    QStringList headers;
    headers << "Offset" << "Name" << "Value" << "Value";
    FileHeaderTable->setHorizontalHeaderLabels(headers);
    OptionalHeaderTable->setHorizontalHeaderLabels(headers);

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, file_header.Machine)), std::ios::beg);
    FileHeaderTable->setItem(0, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    FileHeaderTable->setItem(0, 1, new QTableWidgetItem("Machine"));
    FileHeaderTable->setItem(0, 2, new QTableWidgetItem(QString::number(nt_header64.file_header.Machine, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, file_header.NumberOfSections)), std::ios::beg);
    FileHeaderTable->setItem(1, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    FileHeaderTable->setItem(1, 1, new QTableWidgetItem("Sections Count"));
    FileHeaderTable->setItem(1, 2, new QTableWidgetItem(QString::number(nt_header64.file_header.NumberOfSections, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, file_header.TimeDateStamp)), std::ios::beg);
    FileHeaderTable->setItem(2, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    FileHeaderTable->setItem(2, 1, new QTableWidgetItem("Time Date Stamp"));
    FileHeaderTable->setItem(2, 2, new QTableWidgetItem(QString::number(nt_header64.file_header.TimeDateStamp, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, file_header.PointerToSymbolTable)), std::ios::beg);
    FileHeaderTable->setItem(3, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    FileHeaderTable->setItem(3, 1, new QTableWidgetItem("Pointer to Symbol Table"));
    FileHeaderTable->setItem(3, 2, new QTableWidgetItem(QString::number(nt_header64.file_header.PointerToSymbolTable, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, file_header.NumberOfSymbols)), std::ios::beg);
    FileHeaderTable->setItem(4, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    FileHeaderTable->setItem(4, 1, new QTableWidgetItem("Number of Symbols"));
    FileHeaderTable->setItem(4, 2, new QTableWidgetItem(QString::number(nt_header64.file_header.NumberOfSymbols, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, file_header.SizeOfOptionalHeader)), std::ios::beg);
    FileHeaderTable->setItem(5, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    FileHeaderTable->setItem(5, 1, new QTableWidgetItem("Size of OptionalHeader"));
    FileHeaderTable->setItem(5, 2, new QTableWidgetItem(QString::number(nt_header64.file_header.SizeOfOptionalHeader, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, file_header.Characteristics)), std::ios::beg);
    FileHeaderTable->setItem(6, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    FileHeaderTable->setItem(6, 1, new QTableWidgetItem("Characteristics"));
    FileHeaderTable->setItem(6, 2, new QTableWidgetItem(QString::number(nt_header64.file_header.Characteristics, 16).toUpper()));

    PETabs->addTab(FileHeaderTable, "File Header");

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.Magic)), std::ios::beg);
    OptionalHeaderTable->setItem(0, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(0, 1, new QTableWidgetItem("Magic"));
    OptionalHeaderTable->setItem(0, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.Magic, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MajorLinkerVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(1, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(1, 1, new QTableWidgetItem("Linker Ver. (Major)"));
    OptionalHeaderTable->setItem(1, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MajorLinkerVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MinorLinkerVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(2, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(2, 1, new QTableWidgetItem("Linker Ver. (Minor)"));
    OptionalHeaderTable->setItem(2, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MinorLinkerVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfCode)), std::ios::beg);
    OptionalHeaderTable->setItem(3, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(3, 1, new QTableWidgetItem("Size of Code"));
    OptionalHeaderTable->setItem(3, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfCode, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfInitializedData)), std::ios::beg);
    OptionalHeaderTable->setItem(4, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(4, 1, new QTableWidgetItem("Size of Initialized Data"));
    OptionalHeaderTable->setItem(4, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfInitializedData, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfUninitializedData)), std::ios::beg);
    OptionalHeaderTable->setItem(5, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(5, 1, new QTableWidgetItem("Size of Uninitialized Data"));
    OptionalHeaderTable->setItem(5, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfUninitializedData, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.AddressOfEntryPoint)), std::ios::beg);
    OptionalHeaderTable->setItem(6, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(6, 1, new QTableWidgetItem("Entry Point"));
    OptionalHeaderTable->setItem(6, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.AddressOfEntryPoint, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.BaseOfCode)), std::ios::beg);
    OptionalHeaderTable->setItem(7, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(7, 1, new QTableWidgetItem("Base of Code"));
    OptionalHeaderTable->setItem(7, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.BaseOfCode, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.ImageBase)), std::ios::beg);
    OptionalHeaderTable->setItem(9, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(9, 1, new QTableWidgetItem("Image Base"));
    OptionalHeaderTable->setItem(9, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.ImageBase, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SectionAlignment)), std::ios::beg);
    OptionalHeaderTable->setItem(10, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(10, 1, new QTableWidgetItem("Section Alignment"));
    OptionalHeaderTable->setItem(10, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SectionAlignment, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.FileAlignment)), std::ios::beg);
    OptionalHeaderTable->setItem(11, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(11, 1, new QTableWidgetItem("File Alignment"));
    OptionalHeaderTable->setItem(11, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.FileAlignment, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MajorOperatingSystemVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(12, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(12, 1, new QTableWidgetItem("OS Ver. (Major)"));
    OptionalHeaderTable->setItem(12, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MajorOperatingSystemVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MinorOperatingSystemVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(13, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(13, 1, new QTableWidgetItem("OS Ver. (Minor)"));
    OptionalHeaderTable->setItem(13, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MinorOperatingSystemVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MajorImageVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(14, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(14, 1, new QTableWidgetItem("Image Ver. (Major)"));
    OptionalHeaderTable->setItem(14, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MajorImageVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MinorImageVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(15, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(15, 1, new QTableWidgetItem("Image Ver. (Minor)"));
    OptionalHeaderTable->setItem(15, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MinorImageVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MajorSubsystemVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(16, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(16, 1, new QTableWidgetItem("Subsystem Ver. (Major)"));
    OptionalHeaderTable->setItem(16, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MajorSubsystemVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.MinorSubsystemVersion)), std::ios::beg);
    OptionalHeaderTable->setItem(17, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(17, 1, new QTableWidgetItem("Subsystem Ver. Minor)"));
    OptionalHeaderTable->setItem(17, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.MinorSubsystemVersion, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.Win32VersionValue)), std::ios::beg);
    OptionalHeaderTable->setItem(18, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(18, 1, new QTableWidgetItem("Win32 Version Value"));
    OptionalHeaderTable->setItem(18, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.Win32VersionValue, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfImage)), std::ios::beg);
    OptionalHeaderTable->setItem(19, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(19, 1, new QTableWidgetItem("Size of Image"));
    OptionalHeaderTable->setItem(19, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfImage, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfHeaders)), std::ios::beg);
    OptionalHeaderTable->setItem(20, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(20, 1, new QTableWidgetItem("Size of Headers"));
    OptionalHeaderTable->setItem(20, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfHeaders, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.CheckSum)), std::ios::beg);
    OptionalHeaderTable->setItem(21, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(21, 1, new QTableWidgetItem("Checksum"));
    OptionalHeaderTable->setItem(21, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.CheckSum, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.Subsystem)), std::ios::beg);
    OptionalHeaderTable->setItem(22, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(22, 1, new QTableWidgetItem("Subsystem"));
    OptionalHeaderTable->setItem(22, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.Subsystem, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DllCharacteristics)), std::ios::beg);
    OptionalHeaderTable->setItem(23, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(23, 1, new QTableWidgetItem("DLL Characteristics"));
    OptionalHeaderTable->setItem(23, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DllCharacteristics, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfStackReserve)), std::ios::beg);
    OptionalHeaderTable->setItem(24, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(24, 1, new QTableWidgetItem("Size of Stack Reserve"));
    OptionalHeaderTable->setItem(24, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfStackReserve, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfStackCommit)), std::ios::beg);
    OptionalHeaderTable->setItem(25, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(25, 1, new QTableWidgetItem("Size of Stack Commit"));
    OptionalHeaderTable->setItem(25, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfStackCommit, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfHeapReserve)), std::ios::beg);
    OptionalHeaderTable->setItem(26, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(26, 1, new QTableWidgetItem("Size of Heap Reserve"));
    OptionalHeaderTable->setItem(26, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfHeapReserve, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.SizeOfHeapCommit)), std::ios::beg);
    OptionalHeaderTable->setItem(27, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(27, 1, new QTableWidgetItem("Size of Heap Commit"));
    OptionalHeaderTable->setItem(27, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.SizeOfHeapCommit, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.LoaderFlags)), std::ios::beg);
    OptionalHeaderTable->setItem(28, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(28, 1, new QTableWidgetItem("Loader Flags"));
    OptionalHeaderTable->setItem(28, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.LoaderFlags, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.NumberOfRvaAndSizes)), std::ios::beg);
    OptionalHeaderTable->setItem(29, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    OptionalHeaderTable->setItem(29, 1, new QTableWidgetItem("Number of RVAs and Sizes"));
    OptionalHeaderTable->setItem(29, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.NumberOfRvaAndSizes, 16).toUpper()));

    OptionalHeaderTable->setItem(30, 1, new QTableWidgetItem("Data Directory"));

    auto * AddressHeader = new QTableWidgetItem("Address");
    auto * SizeHeader = new QTableWidgetItem("Size");

    QColor lightBlue(173, 216, 230);

    AddressHeader->setBackground(lightBlue);
    OptionalHeaderTable->setItem(30, 2, AddressHeader);
    SizeHeader->setBackground(lightBlue);
    OptionalHeaderTable->setItem(30, 3, SizeHeader);

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_EXPORT])), std::ios::beg);
    OptionalHeaderTable->setItem(31, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * ExportDirectoryName = new QTableWidgetItem("Export Directory");
    ExportDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(31, 1, ExportDirectoryName);
    OptionalHeaderTable->setItem(31, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_EXPORT].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(31, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_EXPORT].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_IMPORT])), std::ios::beg);
    OptionalHeaderTable->setItem(32, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * ImportDirectoryName = new QTableWidgetItem("Import Directory");
    ImportDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(32, 1, ImportDirectoryName);
    OptionalHeaderTable->setItem(32, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_IMPORT].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(32, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_IMPORT].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_RESOURCE])), std::ios::beg);
    OptionalHeaderTable->setItem(33, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * ResourceDirectoryName = new QTableWidgetItem("Resource Directory");
    ResourceDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(33, 1, ResourceDirectoryName);
    OptionalHeaderTable->setItem(33, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_RESOURCE].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(33, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_RESOURCE].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_EXCEPTION])), std::ios::beg);
    OptionalHeaderTable->setItem(34, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * ExceptionDirectoryName = new QTableWidgetItem("Exception Directory");
    ExceptionDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(34, 1, ExceptionDirectoryName);
    OptionalHeaderTable->setItem(34, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(34, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_EXCEPTION].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_SECURITY])), std::ios::beg);
    OptionalHeaderTable->setItem(35, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * SecurityDirectoryName = new QTableWidgetItem("Security Directory");
    SecurityDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(35, 1, SecurityDirectoryName);
    OptionalHeaderTable->setItem(35, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_SECURITY].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(35, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_SECURITY].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_BASERELOC])), std::ios::beg);
    OptionalHeaderTable->setItem(36, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * BaseRelocationTableName = new QTableWidgetItem("Base Relocation Table");
    BaseRelocationTableName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(36, 1, BaseRelocationTableName);
    OptionalHeaderTable->setItem(36, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_BASERELOC].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(36, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_BASERELOC].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_DEBUG])), std::ios::beg);
    OptionalHeaderTable->setItem(37, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * DebugDirectoryName = new QTableWidgetItem("Debug Directory");
    DebugDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(37, 1, DebugDirectoryName);
    OptionalHeaderTable->setItem(37, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_DEBUG].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(37, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_DEBUG].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_ARCHITECTURE])), std::ios::beg);
    OptionalHeaderTable->setItem(38, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * ArchitectureSpecificDataName = new QTableWidgetItem("Architecture Specific Data");
    ArchitectureSpecificDataName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(38, 1, ArchitectureSpecificDataName);
    OptionalHeaderTable->setItem(38, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(38, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_ARCHITECTURE].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_GLOBALPTR])), std::ios::beg);
    OptionalHeaderTable->setItem(39, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * RVAOfGlobalPointerName = new QTableWidgetItem("RVA of Global Pointer");
    RVAOfGlobalPointerName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(39, 1, RVAOfGlobalPointerName);
    OptionalHeaderTable->setItem(39, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(39, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_GLOBALPTR].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_TLS])), std::ios::beg);
    OptionalHeaderTable->setItem(40, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * TLSDirectoryName = new QTableWidgetItem("TLS Directory");
    TLSDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(40, 1, TLSDirectoryName);
    OptionalHeaderTable->setItem(40, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_TLS].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(40, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_TLS].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_BOUND_IMPORT])), std::ios::beg);
    OptionalHeaderTable->setItem(41, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * BoundImportDirectoryName = new QTableWidgetItem("Bound Import Directory");
    BoundImportDirectoryName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(41, 1, BoundImportDirectoryName);
    OptionalHeaderTable->setItem(41, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(41, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_BOUND_IMPORT].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_IAT])), std::ios::beg);
    OptionalHeaderTable->setItem(42, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * ImportAddressTableName = new QTableWidgetItem("Import Address Table");
    ImportAddressTableName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(42, 1, ImportAddressTableName);
    OptionalHeaderTable->setItem(42, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_IAT].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(42, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_IAT].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_DELAY_IMPORT])), std::ios::beg);
    OptionalHeaderTable->setItem(43, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * DelayLoadImportName = new QTableWidgetItem("Delay Load Import Descriptors");
    DelayLoadImportName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(43, 1, DelayLoadImportName);
    OptionalHeaderTable->setItem(43, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(43, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_DELAY_IMPORT].Size, 16).toUpper()));

    file.seekg((unsigned int) (dos_header.e_lfanew + offsetof(NTHeader_64, optional_header64.DataDirectory[DIRECTORY_ENTRY_COM_DESCRIPTOR])), std::ios::beg);
    OptionalHeaderTable->setItem(44, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    auto * NetHeaderName = new QTableWidgetItem(".NET header");
    NetHeaderName->setBackground(lightBlue);
    OptionalHeaderTable->setItem(44, 1, NetHeaderName);
    OptionalHeaderTable->setItem(44, 2, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, 16).toUpper()));
    OptionalHeaderTable->setItem(44, 3, new QTableWidgetItem(QString::number(nt_header64.optional_header64.DataDirectory[DIRECTORY_ENTRY_COM_DESCRIPTOR].Size, 16).toUpper()));

    PETabs->addTab(OptionalHeaderTable, "Optional Header");
}
void GuiPE::GUIDosHeader()
{
    file.read(
            std::bit_cast<char*>(&dos_header),
            sizeof(dos_header)
    );

    formatTable(DosTable);

    QStringList headers;
    headers << "Offset" << "Name" << "Value";
    DosTable->setHorizontalHeaderLabels(headers);

    file.seekg(0, std::ios::beg);
    DosTable->setItem(0, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(0, 1, new QTableWidgetItem("Magic"));
    DosTable->setItem(0, 2, new QTableWidgetItem(QString::number(dos_header.e_magic, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_cblp), std::ios::beg);
    DosTable->setItem(1, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(1, 1, new QTableWidgetItem("Bytes on last page of file"));
    DosTable->setItem(1, 2, new QTableWidgetItem(QString::number(dos_header.e_cblp, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_cp), std::ios::beg);
    DosTable->setItem(2, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(2, 1, new QTableWidgetItem("Pages in file"));
    DosTable->setItem(2, 2, new QTableWidgetItem(QString::number(dos_header.e_cp, 16)));

    file.seekg(offsetof(DOS_HEADER, e_crlc), std::ios::beg);
    DosTable->setItem(3, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(3, 1, new QTableWidgetItem("Relocations"));
    DosTable->setItem(3, 2, new QTableWidgetItem(QString::number(dos_header.e_crlc, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_cparhdr), std::ios::beg);
    DosTable->setItem(4, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(4, 1, new QTableWidgetItem("Size of header in paragraphs"));
    DosTable->setItem(4, 2, new QTableWidgetItem(QString::number(dos_header.e_cparhdr, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_minalloc), std::ios::beg);
    DosTable->setItem(5, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(5, 1, new QTableWidgetItem("Minimum extra paragraphs needed"));
    DosTable->setItem(5, 2, new QTableWidgetItem(QString::number(dos_header.e_minalloc, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_maxalloc), std::ios::beg);
    DosTable->setItem(6, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(6, 1, new QTableWidgetItem("Maximum extra paragraphs needed"));
    DosTable->setItem(6, 2, new QTableWidgetItem(QString::number(dos_header.e_maxalloc, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_ss), std::ios::beg);
    DosTable->setItem(7, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(7, 1, new QTableWidgetItem("Initial (relative) SS value"));
    DosTable->setItem(7, 2, new QTableWidgetItem(QString::number(dos_header.e_ss, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_sp), std::ios::beg);
    DosTable->setItem(8, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(8, 1, new QTableWidgetItem("Initial SP value"));
    DosTable->setItem(8, 2, new QTableWidgetItem(QString::number(dos_header.e_sp, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_csum), std::ios::beg);
    DosTable->setItem(9, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(9, 1, new QTableWidgetItem("Checksum"));
    DosTable->setItem(9, 2, new QTableWidgetItem(QString::number(dos_header.e_csum, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_ip), std::ios::beg);
    DosTable->setItem(10, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(10, 1, new QTableWidgetItem("Initial IP value"));
    DosTable->setItem(10, 2, new QTableWidgetItem(QString::number(dos_header.e_ip, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_cs), std::ios::beg);
    DosTable->setItem(11, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(11, 1, new QTableWidgetItem("Initial (relative) CS value"));
    DosTable->setItem(11, 2, new QTableWidgetItem(QString::number(dos_header.e_cs, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_lfarlc), std::ios::beg);
    DosTable->setItem(12, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(12, 1, new QTableWidgetItem("File address of relocation table"));
    DosTable->setItem(12, 2, new QTableWidgetItem(QString::number(dos_header.e_lfarlc, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_ovno), std::ios::beg);
    DosTable->setItem(13, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(13, 1, new QTableWidgetItem("Overlay number"));
    DosTable->setItem(13, 2, new QTableWidgetItem(QString::number(dos_header.e_ovno, 16).toUpper()));

    std::string e_res_values;
    for(int i = 0; i < 4; i++) {
        if (i != 0)
            e_res_values += ", ";
        e_res_values += QString::number(dos_header.e_res[i], 16).toUpper().toStdString();
    }

    file.seekg(offsetof(DOS_HEADER, e_res), std::ios::beg);
    DosTable->setItem(14, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(14, 1, new QTableWidgetItem("Reserved word[4]"));
    DosTable->setItem(14, 2, new QTableWidgetItem(QString::fromStdString(e_res_values)));

    file.seekg(offsetof(DOS_HEADER, e_oemid), std::ios::beg);
    DosTable->setItem(15, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(15, 1, new QTableWidgetItem("OEM identifier (for OEM information)"));
    DosTable->setItem(15, 2, new QTableWidgetItem(QString::number(dos_header.e_oemid, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_oeminfo), std::ios::beg);
    DosTable->setItem(16, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(16, 1, new QTableWidgetItem("OEM information"));
    DosTable->setItem(16, 2, new QTableWidgetItem(QString::number(dos_header.e_oeminfo, 16).toUpper()));

    file.seekg(offsetof(DOS_HEADER, e_ovno), std::ios::beg);
    DosTable->setItem(17, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(17, 1, new QTableWidgetItem("Overlay number"));
    DosTable->setItem(17, 2, new QTableWidgetItem(QString::number(dos_header.e_ovno, 16).toUpper()));

    std::string e_res2_values;
    for(int i = 0; i < 9; i++) {
        if (i != 0)
            e_res2_values += ", ";
        e_res2_values += QString::number(dos_header.e_res2[i], 16).toUpper().toStdString();
    }

    file.seekg(offsetof(DOS_HEADER, e_res2), std::ios::beg);
    DosTable->setItem(18, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(18, 1, new QTableWidgetItem("Reserved word[10]"));
    DosTable->setItem(18, 2, new QTableWidgetItem(QString::fromStdString(e_res2_values)));

    file.seekg(offsetof(DOS_HEADER, e_lfanew), std::ios::beg);
    DosTable->setItem(19, 0, new QTableWidgetItem(QString::number(file.tellg(), 16).toUpper()));
    DosTable->setItem(19, 1, new QTableWidgetItem("File address header"));
    DosTable->setItem(19, 2, new QTableWidgetItem(QString::number(dos_header.e_lfanew, 16).toUpper()));

    PETabs->addTab(DosTable, "Dos Header");
}

void GuiPE::Load(const std::string& file_path)
{
    file.open(file_path, std::ios::binary);

    PETabs = new QTabWidget;

    DosTable = new QTableWidget(20, 3);
    FileHeaderTable = new QTableWidget(7, 3);
    OptionalHeaderTable = new QTableWidget(45, 4);
    SectionHeaderTable = new QTableWidget(20, 10);
    ImportsTable = new QTableWidget(20, 8);
    ExceptionsTable = new QTableWidget(0, 4);
    BaseRelocationTable = new QTableWidget(0, 4);
    TlsTable = new QTableWidget(6, 3);
    TlsCallbackTable = new QTableWidget(0, 2);

    GUIDosHeader();
    GUINtHeader();
    GUISections();
    GUIImports();
    GUIExceptions();
    GUIBaseRelocations();
    GUITLS();
}
