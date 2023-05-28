#include "headers/GuiPE.hpp"

#include <QApplication>
#include <QMainWindow>
#include <QScrollBar>

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    QApplication guiApp(argc, argv);

    GuiPE file;
    std::string file_path = R"(C:\Riot Games\League of Legends\Game\League of Legends.exe)";
    file.Load(file_path);

    QMainWindow main_window;
    QIcon windowIcon(R"(C:\Users\FindW\Desktop\5679795.png)");
    main_window.resize(901, 675);
    main_window.setWindowTitle("PE64 Parser v1.2");
    main_window.setWindowIcon(windowIcon);

    auto * centralWidget = new QWidget(&main_window);
    auto * centralLayout = new QVBoxLayout(centralWidget);

    // Create the top layout for the hex viewer and char table viewer
    auto * topLayout = new QHBoxLayout();
    centralLayout->addLayout(topLayout);

    file.createHexAndCharByteViewer(nullptr, file_path, 32, 0);
    QTableWidget* hexViewerTable = file.hexViewer;
    QTableWidget* charViewerTable = file.charViewer;

    topLayout->addWidget(hexViewerTable);
    topLayout->addWidget(charViewerTable);

    QObject::connect(hexViewerTable->verticalScrollBar(), &QScrollBar::valueChanged, charViewerTable->verticalScrollBar(), &QScrollBar::setValue);
    QObject::connect(charViewerTable->verticalScrollBar(), &QScrollBar::valueChanged, hexViewerTable->verticalScrollBar(), &QScrollBar::setValue);

    // Create the bottom layout for the PE tables and other tables
    auto * bottomLayout = new QVBoxLayout();
    centralLayout->addLayout(bottomLayout);

    bottomLayout->addWidget(file.getTabs());

    main_window.setCentralWidget(centralWidget);
    main_window.show();

    return QApplication::exec();
}