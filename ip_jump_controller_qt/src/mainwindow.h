#pragma once

#include <QMainWindow>
#include <QSplitter>
#include <QScrollArea>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QRadioButton>
#include <QButtonGroup>
#include <QLabel>
#include <QTextEdit>
#include <QTableWidget>
#include <QHeaderView>
#include <QProcess>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QStatusBar>
#include <QFile>
#include <QTimer>
#include <QShortcut>
#include "mockserver.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStateChanged();
    void onStartStop();
    void onBindAddrChanged(const QString &text);
    void onQueueJump();
    void onClearLogs();
    void onLogDoubleClicked(int row, int col);
    void onDetectNetwork();
    void onUpdateNetInfo();
    void onRestoreNetInfo();
    void onTestConnection();
    void onCycleEnabledChanged(bool checked);
    void onCycleIpPoolChanged(const QString &text);
    void onCycleGatewayChanged(const QString &text);
    void onCycleIntervalChanged();
    void onCyclePrefixChanged();
    void onCycleModeChanged();

private:
    void setupUi();
    void refreshUi();

    MockServerState m_state;
    MockServer m_server;

    // --- Left panel widgets ---

    // Mock Server
    QSpinBox *m_portSpin = nullptr;
    QLineEdit *m_bindEdit = nullptr;
    QPushButton *m_startStopBtn = nullptr;
    QLabel *m_statusLabel = nullptr;
    QLabel *m_agentUrlLabel = nullptr;

    // Agent Status
    QLabel *m_lblHost = nullptr;
    QLabel *m_lblUid = nullptr;
    QLabel *m_lblIp = nullptr;
    QLabel *m_lblJump = nullptr;
    QLabel *m_lblQueue = nullptr;
    QLabel *m_lblReqs = nullptr;
    QLabel *m_lblJumpsSent = nullptr;

    // IP Jump
    QLineEdit *m_srcIpEdit = nullptr;
    QLineEdit *m_tgtIpEdit = nullptr;
    QLineEdit *m_gwEdit = nullptr;
    QRadioButton *m_modeKeep = nullptr;
    QRadioButton *m_modeForce = nullptr;
    QSpinBox *m_activeSpin = nullptr;
    QSpinBox *m_agingSpin = nullptr;
    QSpinBox *m_prefixSpin = nullptr;

    // Cycle
    QCheckBox *m_cycleEnable = nullptr;
    QLineEdit *m_cyclePoolEdit = nullptr;
    QLineEdit *m_cycleGwEdit = nullptr;
    QSpinBox *m_cycleIntervalSpin = nullptr;
    QSpinBox *m_cyclePrefixSpin = nullptr;
    QRadioButton *m_cycleModeKeep = nullptr;
    QRadioButton *m_cycleModeForce = nullptr;
    QLabel *m_cycleDisplay = nullptr;

    // Quick Commands
    QLineEdit *m_configPathEdit = nullptr;
    QTextEdit *m_networkInfoText = nullptr;

    // Right panel
    QLabel *m_logCountLabel = nullptr;
    QTableWidget *m_logTable = nullptr;

    // Network
    QNetworkAccessManager m_netMgr;
};
