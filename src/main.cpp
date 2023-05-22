#include "headers/GuiPE.hpp"
#include "GuiPE.cpp"

#include <QApplication>
#include <QMainWindow>
#include <QLabel>

int main([[maybe_unused]] int argc, [[maybe_unused]] char * argv[])
{
    QApplication guiApp(argc, argv);

    GuiPE file;
    file.Load(R"(C:\Riot Games\League of Legends\Game\League of Legends.exe)");

    auto * layout = new QVBoxLayout;
    auto * centralWidget = new QWidget;

    layout->addWidget(file.getTabs());
    centralWidget->setLayout(layout);

    QMainWindow main_window;
    QIcon windowIcon(R"(C:\Users\FindW\Desktop\5679795.png)");
    main_window.resize(901,  675);
    main_window.setWindowTitle("PE64 Parser v1.0");
    main_window.setWindowIcon(windowIcon);
    main_window.setCentralWidget(centralWidget);

    main_window.show();

    return QApplication::exec();
}
