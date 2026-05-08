#include <QApplication>
#include <QPalette>
#include <QStyleFactory>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("IP Jump Controller");
    app.setApplicationVersion("1.0.0");

    // Dark palette matching the Flutter dark theme
    QPalette p;
    p.setColor(QPalette::Window,          QColor(30, 30, 30));
    p.setColor(QPalette::WindowText,       Qt::white);
    p.setColor(QPalette::Base,            QColor(42, 42, 42));
    p.setColor(QPalette::AlternateBase,   QColor(50, 50, 50));
    p.setColor(QPalette::ToolTipBase,     QColor(60, 60, 60));
    p.setColor(QPalette::ToolTipText,     Qt::white);
    p.setColor(QPalette::Text,            Qt::white);
    p.setColor(QPalette::Button,          QColor(53, 53, 53));
    p.setColor(QPalette::ButtonText,      Qt::white);
    p.setColor(QPalette::BrightText,      Qt::red);
    p.setColor(QPalette::Link,            QColor(63, 81, 181));
    p.setColor(QPalette::Highlight,       QColor(63, 81, 181));
    p.setColor(QPalette::HighlightedText, Qt::white);
    p.setColor(QPalette::Disabled, QPalette::Text, QColor(128, 128, 128));
    p.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(128, 128, 128));
    app.setPalette(p);
    app.setStyle(QStyleFactory::create("Fusion"));

    MainWindow window;
    window.resize(1100, 720);
    window.show();
    return app.exec();
}
