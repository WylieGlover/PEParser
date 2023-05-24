#include "headers/GuiPE.hpp"

#include <QApplication>
#include <QMainWindow>

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    QApplication guiApp(argc, argv);

    GuiPE file;
    std::string file_path = R"(C:\Users\FindW\Desktop\Personal Projects\cpp\yo.exe)";
    file.Load(file_path);

    QMainWindow main_window;
    QIcon windowIcon(R"(C:\Users\FindW\Desktop\5679795.png)");
    main_window.resize(901, 675);
    main_window.setWindowTitle("PE64 Parser v1.2");
    main_window.setWindowIcon(windowIcon);

    auto * centralWidget = new QWidget(&main_window);
    auto * centralLayout = new QVBoxLayout(centralWidget);

    file.createHexByteViewer(centralWidget, file_path, 32, 0);
    centralLayout->addWidget(centralWidget->findChild<QTableWidget*>());
    centralLayout->addWidget(file.getTabs());

    main_window.setCentralWidget(centralWidget);
    main_window.show();

    return QApplication::exec();
}