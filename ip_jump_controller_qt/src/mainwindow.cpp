#include "mainwindow.h"
#include <QApplication>
#include <QIcon>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QRegularExpression>
#include <QDir>
#include <QTextStream>
#include <utility>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_server(&m_state, this)
{
    setWindowTitle("IP Jump Controller");
    setupUi();

    connect(&m_state, &MockServerState::changed, this, &MainWindow::refreshUi);
    connect(&m_state, &MockServerState::changed, this, &MainWindow::onStateChanged, Qt::QueuedConnection);

    QTimer::singleShot(200, this, &MainWindow::onDetectNetwork);
}

MainWindow::~MainWindow() = default;

// ==================== makeSection helper ====================

static std::pair<QGroupBox *, QVBoxLayout *> makeSection(const QString &title, const QIcon &icon)
{
    auto *box = new QGroupBox();
    auto *mainLayout = new QVBoxLayout(box);
    mainLayout->setContentsMargins(10, 8, 10, 8);

    auto *titleRow = new QHBoxLayout();
    auto *iconLabel = new QLabel();
    iconLabel->setPixmap(icon.pixmap(18, 18));
    auto *titleLabel = new QLabel(title);
    titleLabel->setStyleSheet("font-weight: bold; font-size: 13px; color: #9fa8da;");
    titleRow->addWidget(iconLabel);
    titleRow->addWidget(titleLabel);
    titleRow->addStretch();
    mainLayout->addLayout(titleRow);

    return {box, mainLayout};
}

// ==================== UI Setup ====================

void MainWindow::setupUi()
{
    QWidget *central = new QWidget(this);
    setCentralWidget(central);
    QHBoxLayout *rootLayout = new QHBoxLayout(central);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    QSplitter *splitter = new QSplitter(Qt::Horizontal);
    rootLayout->addWidget(splitter);

    // ========== Left Panel ==========
    QScrollArea *scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setMinimumWidth(420);
    scroll->setMaximumWidth(500);
    scroll->setFrameShape(QFrame::NoFrame);

    QWidget *leftPanel = new QWidget();
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(12, 12, 12, 12);
    leftLayout->setSpacing(8);

    // --- Mock Server ---
    {
        auto [box, lay] = makeSection("Mock Server",
            QIcon::fromTheme("network-server", QIcon::fromTheme("applications-system")));

        QHBoxLayout *row1 = new QHBoxLayout();
        m_portSpin = new QSpinBox();
        m_portSpin->setRange(1, 65535);
        m_portSpin->setValue(8080);
        m_portSpin->setPrefix("Port: ");
        m_portSpin->setMinimumWidth(100);

        m_bindEdit = new QLineEdit("0.0.0.0");
        m_bindEdit->setPlaceholderText("Bind Address");
        m_bindEdit->setMaximumWidth(130);
        connect(m_bindEdit, &QLineEdit::textChanged, this, &MainWindow::onBindAddrChanged);

        m_startStopBtn = new QPushButton("Start");
        m_startStopBtn->setStyleSheet("QPushButton { background-color: #2e7d32; color: white; padding: 6px 14px; }");
        connect(m_startStopBtn, &QPushButton::clicked, this, &MainWindow::onStartStop);

        m_statusLabel = new QLabel("Stopped");
        m_statusLabel->setStyleSheet("color: #888; font-size: 11px;");

        row1->addWidget(m_portSpin);
        row1->addWidget(m_bindEdit);
        row1->addWidget(m_startStopBtn);
        row1->addWidget(m_statusLabel);
        row1->addStretch();
        lay->addLayout(row1);

        m_agentUrlLabel = new QLabel();
        m_agentUrlLabel->setStyleSheet("color: #ffb74d; font-size: 11px;");
        m_agentUrlLabel->setVisible(false);
        lay->addWidget(m_agentUrlLabel);

        leftLayout->addWidget(box);
    }

    // --- Agent Status ---
    {
        auto [box, lay] = makeSection("Agent Status",
            QIcon::fromTheme("computer", QIcon::fromTheme("drive-harddisk")));
        QFormLayout *form = new QFormLayout();
        form->setSpacing(4);

        auto makeInfo = [&](const QString &label) -> QLabel * {
            QLabel *v = new QLabel("-");
            v->setStyleSheet("font-weight: bold; font-size: 12px;");
            form->addRow(new QLabel(label), v);
            return v;
        };
        m_lblHost = makeInfo("Host");
        m_lblUid = makeInfo("UID");
        m_lblIp = makeInfo("Logical Primary IP");
        m_lblJump = makeInfo("Last Jump");
        m_lblQueue = makeInfo("Queue");
        m_lblReqs = makeInfo("Requests");
        m_lblJumpsSent = makeInfo("Jumps Sent");

        lay->addLayout(form);
        leftLayout->addWidget(box);
    }

    // --- IP Jump Instruction ---
    {
        auto [box, lay] = makeSection("IP Jump Instruction",
            QIcon::fromTheme("go-jump", QIcon::fromTheme("edit-undo")));

        m_srcIpEdit = new QLineEdit();
        m_srcIpEdit->setPlaceholderText("Source IP (empty=auto)");
        m_tgtIpEdit = new QLineEdit();
        m_tgtIpEdit->setPlaceholderText("Target IP *");
        m_gwEdit = new QLineEdit();
        m_gwEdit->setPlaceholderText("Gateway (empty=auto)");
        lay->addWidget(m_srcIpEdit);
        lay->addWidget(m_tgtIpEdit);
        lay->addWidget(m_gwEdit);

        QHBoxLayout *modeRow = new QHBoxLayout();
        modeRow->addWidget(new QLabel("Mode:"));
        m_modeKeep = new QRadioButton("1-Keep");
        m_modeForce = new QRadioButton("2-Force");
        m_modeKeep->setChecked(true);
        auto *modeGrp = new QButtonGroup(this);
        modeGrp->addButton(m_modeKeep, 1);
        modeGrp->addButton(m_modeForce, 2);
        modeRow->addWidget(m_modeKeep);
        modeRow->addWidget(m_modeForce);
        modeRow->addStretch();
        lay->addLayout(modeRow);

        QHBoxLayout *paramRow = new QHBoxLayout();
        m_activeSpin = new QSpinBox();
        m_activeSpin->setRange(0, 99999);
        m_activeSpin->setPrefix("Active(s): ");
        m_agingSpin = new QSpinBox();
        m_agingSpin->setRange(0, 99999);
        m_agingSpin->setPrefix("Aging(min): ");
        m_prefixSpin = new QSpinBox();
        m_prefixSpin->setRange(1, 32);
        m_prefixSpin->setValue(24);
        m_prefixSpin->setPrefix("Prefix: ");
        paramRow->addWidget(m_activeSpin);
        paramRow->addWidget(m_agingSpin);
        paramRow->addWidget(m_prefixSpin);
        lay->addLayout(paramRow);

        QHBoxLayout *btnRow = new QHBoxLayout();
        QPushButton *queueBtn = new QPushButton("Queue Jump");
        queueBtn->setStyleSheet("QPushButton { background-color: #3949ab; color: white; padding: 6px 14px; }");
        connect(queueBtn, &QPushButton::clicked, this, &MainWindow::onQueueJump);
        QPushButton *clearQBtn = new QPushButton("Clear Queue");
        connect(clearQBtn, &QPushButton::clicked, [this]() { m_state.clearQueue(); });
        btnRow->addWidget(queueBtn);
        btnRow->addWidget(clearQBtn);
        btnRow->addStretch();
        lay->addLayout(btnRow);

        leftLayout->addWidget(box);
    }

    // --- Cycle Strategy ---
    {
        auto [box, lay] = makeSection("Cycle Strategy (Periodic)",
            QIcon::fromTheme("view-refresh", QIcon::fromTheme("edit-redo")));

        m_cycleEnable = new QCheckBox("Enable Cycle");
        connect(m_cycleEnable, &QCheckBox::toggled, this, &MainWindow::onCycleEnabledChanged);
        lay->addWidget(m_cycleEnable);

        m_cyclePoolEdit = new QLineEdit();
        m_cyclePoolEdit->setPlaceholderText("e.g. 192.168.3.88,192.168.3.40,192.167.3.115");
        connect(m_cyclePoolEdit, &QLineEdit::textChanged, this, &MainWindow::onCycleIpPoolChanged);
        lay->addWidget(m_cyclePoolEdit);

        QHBoxLayout *cycleRow1 = new QHBoxLayout();
        m_cycleGwEdit = new QLineEdit();
        m_cycleGwEdit->setPlaceholderText("Gateway (empty=auto)");
        connect(m_cycleGwEdit, &QLineEdit::textChanged, this, &MainWindow::onCycleGatewayChanged);
        m_cycleIntervalSpin = new QSpinBox();
        m_cycleIntervalSpin->setRange(1, 99999);
        m_cycleIntervalSpin->setValue(30);
        m_cycleIntervalSpin->setPrefix("Interval(s): ");
        connect(m_cycleIntervalSpin, QOverload<int>::of(&QSpinBox::valueChanged),
                [this](int) { onCycleIntervalChanged(); });
        m_cyclePrefixSpin = new QSpinBox();
        m_cyclePrefixSpin->setRange(1, 32);
        m_cyclePrefixSpin->setValue(24);
        m_cyclePrefixSpin->setPrefix("Prefix: ");
        connect(m_cyclePrefixSpin, QOverload<int>::of(&QSpinBox::valueChanged),
                [this](int) { onCyclePrefixChanged(); });
        cycleRow1->addWidget(m_cycleGwEdit);
        cycleRow1->addWidget(m_cycleIntervalSpin);
        cycleRow1->addWidget(m_cyclePrefixSpin);
        lay->addLayout(cycleRow1);

        QHBoxLayout *cycleModeRow = new QHBoxLayout();
        cycleModeRow->addWidget(new QLabel("Mode:"));
        m_cycleModeKeep = new QRadioButton("1-Keep");
        m_cycleModeForce = new QRadioButton("2-Force");
        m_cycleModeKeep->setChecked(true);
        auto *cycleModeGrp = new QButtonGroup(this);
        cycleModeGrp->addButton(m_cycleModeKeep, 1);
        cycleModeGrp->addButton(m_cycleModeForce, 2);
        connect(cycleModeGrp, &QButtonGroup::idClicked,
                [this](int) { onCycleModeChanged(); });
        cycleModeRow->addWidget(m_cycleModeKeep);
        cycleModeRow->addWidget(m_cycleModeForce);
        cycleModeRow->addStretch();
        lay->addLayout(cycleModeRow);

        m_cycleDisplay = new QLabel();
        m_cycleDisplay->setStyleSheet("color: #4dd0e1; font-size: 10px; font-family: monospace;");
        m_cycleDisplay->setWordWrap(true);
        m_cycleDisplay->setVisible(false);
        lay->addWidget(m_cycleDisplay);

        leftLayout->addWidget(box);
    }

    // --- Quick Commands ---
    {
        auto [box, lay] = makeSection("Quick Commands",
            QIcon::fromTheme("utilities-terminal", QIcon::fromTheme("application-x-executable")));

        QHBoxLayout *quickRow1 = new QHBoxLayout();
        QPushButton *detectBtn = new QPushButton("Detect Network");
        QPushButton *updateBtn = new QPushButton("Update net_info.ini");
        connect(detectBtn, &QPushButton::clicked, this, &MainWindow::onDetectNetwork);
        connect(updateBtn, &QPushButton::clicked, this, &MainWindow::onUpdateNetInfo);
        quickRow1->addWidget(detectBtn);
        quickRow1->addWidget(updateBtn);
        lay->addLayout(quickRow1);

        QHBoxLayout *quickRow2 = new QHBoxLayout();
        QPushButton *restoreBtn = new QPushButton("Restore net_info.ini");
        QPushButton *testBtn = new QPushButton("Test Connection");
        connect(restoreBtn, &QPushButton::clicked, this, &MainWindow::onRestoreNetInfo);
        connect(testBtn, &QPushButton::clicked, this, &MainWindow::onTestConnection);
        quickRow2->addWidget(restoreBtn);
        quickRow2->addWidget(testBtn);
        quickRow2->addStretch();
        lay->addLayout(quickRow2);

        m_configPathEdit = new QLineEdit("/opt/osec/net_info.ini");
        m_configPathEdit->setPlaceholderText("Config Path");
        lay->addWidget(m_configPathEdit);

        leftLayout->addWidget(box);
    }

    // --- Network Info ---
    {
        auto [box, lay] = makeSection("Network Info",
            QIcon::fromTheme("network-wired", QIcon::fromTheme("preferences-system-network")));
        m_networkInfoText = new QTextEdit();
        m_networkInfoText->setReadOnly(true);
        m_networkInfoText->setFont(QFont("monospace", 10));
        m_networkInfoText->setMaximumHeight(140);
        lay->addWidget(m_networkInfoText);
        leftLayout->addWidget(box);
    }

    leftLayout->addStretch();
    scroll->setWidget(leftPanel);
    splitter->addWidget(scroll);

    // ========== Right Panel (Log) ==========
    QWidget *rightPanel = new QWidget();
    QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(0);

    QWidget *logHeader = new QWidget();
    logHeader->setStyleSheet("background-color: #212121;");
    QHBoxLayout *headerLayout = new QHBoxLayout(logHeader);
    headerLayout->setContentsMargins(12, 6, 12, 6);
    m_logCountLabel = new QLabel("Live Log (0)");
    m_logCountLabel->setStyleSheet("font-weight: bold; color: white;");
    QPushButton *clearLogBtn = new QPushButton("Clear");
    connect(clearLogBtn, &QPushButton::clicked, this, &MainWindow::onClearLogs);
    headerLayout->addWidget(m_logCountLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(clearLogBtn);
    rightLayout->addWidget(logHeader);

    m_logTable = new QTableWidget(0, 4);
    m_logTable->setHorizontalHeaderLabels({"Time", "Dir", "Path", "Summary"});
    m_logTable->horizontalHeader()->setStretchLastSection(true);
    m_logTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_logTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
    m_logTable->horizontalHeader()->resizeSection(1, 40);
    m_logTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Fixed);
    m_logTable->horizontalHeader()->resizeSection(2, 130);
    m_logTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_logTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_logTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_logTable->verticalHeader()->setVisible(false);
    m_logTable->setShowGrid(false);
    m_logTable->setAlternatingRowColors(true);
    m_logTable->setFont(QFont("monospace", 10));
    connect(m_logTable, &QTableWidget::cellDoubleClicked,
            this, &MainWindow::onLogDoubleClicked);
    rightLayout->addWidget(m_logTable);

    splitter->addWidget(rightPanel);
    splitter->setSizes({420, 680});
}

// ==================== State Refresh ====================

void MainWindow::refreshUi()
{
    bool running = m_state.isRunning;
    m_portSpin->setEnabled(!running);
    m_bindEdit->setEnabled(!running);
    m_startStopBtn->setText(running ? "Stop" : "Start");
    m_startStopBtn->setStyleSheet(running
        ? "QPushButton { background-color: #c62828; color: white; padding: 6px 14px; }"
        : "QPushButton { background-color: #2e7d32; color: white; padding: 6px 14px; }");
    m_statusLabel->setText(running ? "Running" : "Stopped");
    m_statusLabel->setStyleSheet(running
        ? "color: #69f0ae; font-size: 11px;"
        : "color: #888; font-size: 11px;");

    if (running) {
        m_agentUrlLabel->setText("Agent URL: http://"
            + m_state.bindAddress + ":" + QString::number(m_state.port));
        m_agentUrlLabel->setVisible(true);
    } else {
        m_agentUrlLabel->setVisible(false);
    }

    m_lblHost->setText(m_state.agentHostName.isEmpty() ? "-" : m_state.agentHostName);
    QString uid = m_state.agentUid;
    m_lblUid->setText(uid.isEmpty() ? "-" : (uid.length() > 12 ? uid.left(12) : uid));
    m_lblIp->setText(m_state.lastAgentIp.isEmpty() ? "-" : m_state.lastAgentIp);
    m_lblJump->setText(m_state.lastJumpStatus.isEmpty() ? "-" : m_state.lastJumpStatus);
    m_lblQueue->setText(QString::number(m_state.instructionQueue.size()) + " pending");
    m_lblReqs->setText(QString::number(m_state.requestCount));
    m_lblJumpsSent->setText(QString::number(m_state.totalJumpsSent));

    if (m_state.cycleStrategy.enabled) {
        const auto &pool = m_state.cycleStrategy.ipPool;
        if (pool.size() >= 2) {
            m_cycleDisplay->setText("Cycle: " + pool.join(" → ") + " → " + pool.first());
            m_cycleDisplay->setStyleSheet("color: #4dd0e1; font-size: 10px; font-family: monospace;");
            m_cycleDisplay->setVisible(true);
        } else {
            m_cycleDisplay->setText("Need at least 2 IPs in pool");
            m_cycleDisplay->setStyleSheet("color: #ef9a9a; font-size: 10px;");
            m_cycleDisplay->setVisible(true);
        }
    } else {
        m_cycleDisplay->setVisible(false);
    }

    m_logCountLabel->setText("Live Log (" + QString::number(m_state.logs.size()) + ")");
    m_logTable->setRowCount(m_state.logs.size());
    for (int i = 0; i < m_state.logs.size(); ++i) {
        const LogEntry &entry = m_state.logs[i];
        m_logTable->setItem(i, 0, new QTableWidgetItem(
            entry.time.toString("hh:mm:ss")));
        m_logTable->setItem(i, 1, new QTableWidgetItem(entry.direction));
        m_logTable->setItem(i, 2, new QTableWidgetItem(entry.path));
        m_logTable->setItem(i, 3, new QTableWidgetItem(entry.summary));

        bool isIn = entry.direction == "in";
        QColor fg = isIn ? QColor("#90caf9") : QColor("#ffcc80");
        for (int c = 0; c < 4; ++c) {
            if (auto *it = m_logTable->item(i, c))
                it->setForeground(fg);
        }
    }
}

// ==================== Actions ====================

void MainWindow::onStartStop()
{
    if (m_state.isRunning) {
        m_server.stop();
    } else {
        m_state.port = m_portSpin->value();
        m_server.start();
    }
}

void MainWindow::onBindAddrChanged(const QString &text)
{
    m_state.bindAddress = text.trimmed();
}

void MainWindow::onQueueJump()
{
    if (m_tgtIpEdit->text().trimmed().isEmpty()) {
        statusBar()->showMessage("Target IP is required", 3000);
        return;
    }

    JumpInstruction inst;
    inst.sourceIp = m_srcIpEdit->text().trimmed();
    inst.targetIp = m_tgtIpEdit->text().trimmed();
    inst.gateway = m_gwEdit->text().trimmed();
    inst.mode = m_modeKeep->isChecked() ? 1 : 2;
    inst.activeTime = m_activeSpin->value();
    inst.agingTime = m_agingSpin->value();
    inst.prefix = m_prefixSpin->value();

    m_state.queueInstruction(inst);

    QString src = inst.sourceIp.isEmpty() ? "auto" : inst.sourceIp;
    statusBar()->showMessage(
        "Jump queued: " + src + " -> " + inst.targetIp + "/"
        + QString::number(inst.prefix) + " (mode=" + QString::number(inst.mode) + ")",
        3000);
}

void MainWindow::onClearLogs()
{
    m_state.clearLogs();
}

void MainWindow::onLogDoubleClicked(int row, int /*col*/)
{
    if (row < 0 || row >= m_state.logs.size()) return;
    const LogEntry &entry = m_state.logs[row];
    if (entry.data.isEmpty()) return;

    QDialog dlg(this);
    dlg.setWindowTitle("Detail");
    dlg.resize(500, 400);

    QVBoxLayout *dlgLayout = new QVBoxLayout(&dlg);
    QTextEdit *text = new QTextEdit();
    text->setReadOnly(true);
    text->setFont(QFont("monospace", 10));
    text->setPlainText(
        QJsonDocument(entry.data).toJson(QJsonDocument::Indented));
    dlgLayout->addWidget(text);

    QDialogButtonBox *btnBox = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(btnBox, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    dlgLayout->addWidget(btnBox);

    dlg.exec();
}

void MainWindow::onDetectNetwork()
{
    auto runProc = [](const QString &prog, const QStringList &args) -> QString {
        QProcess proc;
        proc.start(prog, args);
        proc.waitForFinished(3000);
        return proc.readAllStandardOutput();
    };

    QString ipOut = runProc("ip", {"-o", "-4", "addr", "show"});
    QString routeOut = runProc("ip", {"route", "show", "default"});

    m_networkInfoText->setPlainText(ipOut + "\n" + routeOut);

    if (m_srcIpEdit->text().isEmpty()) {
        for (const QString &line : ipOut.split('\n')) {
            if (line.contains("inet ") && !line.contains("127.0.0.1")) {
                QRegularExpression re("inet (\\S+)");
                auto match = re.match(line);
                if (match.hasMatch()) {
                    QString ip = match.captured(1).split('/').first();
                    m_srcIpEdit->setText(ip);
                    break;
                }
            }
        }
    }

    if (m_gwEdit->text().isEmpty()) {
        for (const QString &line : routeOut.split('\n')) {
            QRegularExpression re("via (\\S+)");
            auto match = re.match(line);
            if (match.hasMatch()) {
                m_gwEdit->setText(match.captured(1));
                break;
            }
        }
    }
}

void MainWindow::onUpdateNetInfo()
{
    QString configPath = m_configPathEdit->text();
    QFile file(configPath);
    if (!file.exists()) {
        statusBar()->showMessage("Config file not found: " + configPath, 3000);
        return;
    }

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QString content = QString::fromUtf8(file.readAll());
    file.close();

    QFile bak(configPath + ".bak");
    if (bak.open(QIODevice::WriteOnly | QIODevice::Text)) {
        bak.write(content.toUtf8());
        bak.close();
    }

    QString bind = m_state.bindAddress;
    QString port = QString::number(m_portSpin->value());
    content.replace(QRegularExpression("SERVERIPPORT=.*"), "SERVERIPPORT=http://" + bind + ":" + port);
    content.replace(QRegularExpression("SERVER_IP=.*"), "SERVER_IP=" + bind);
    content.replace(QRegularExpression("SERVER_PORT=.*"), "SERVER_PORT=" + port);

    if (file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        file.write(content.toUtf8());
        file.close();
        statusBar()->showMessage("Updated " + configPath
            + " -> http://" + bind + ":" + port, 3000);
    }
}

void MainWindow::onRestoreNetInfo()
{
    QString configPath = m_configPathEdit->text();
    QFile bak(configPath + ".bak");
    if (!bak.exists()) {
        statusBar()->showMessage("No backup file found", 3000);
        return;
    }

    if (!bak.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QString content = QString::fromUtf8(bak.readAll());
    bak.close();

    QFile file(configPath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        file.write(content.toUtf8());
        file.close();
        statusBar()->showMessage("Restored from backup", 3000);
    }
}

void MainWindow::onTestConnection()
{
    QString port = QString::number(m_portSpin->value());
    QUrl url("http://127.0.0.1:" + port + "/v1/auth");

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject body;
    body["uid"] = "test";
    body["macid"] = "test";
    body["host_name"] = "qt-test";
    QByteArray jsonBody = QJsonDocument(body).toJson(QJsonDocument::Compact);

    QNetworkReply *reply = m_netMgr.post(req, jsonBody);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() == QNetworkReply::NoError) {
            QString b = reply->readAll();
            QString preview = b.length() > 100 ? b.left(100) + "..." : b;
            statusBar()->showMessage("Mock server OK! Status: "
                + QString::number(reply->attribute(
                    QNetworkRequest::HttpStatusCodeAttribute).toInt())
                + ", Body: " + preview);
        } else {
            statusBar()->showMessage("Connection FAILED: " + reply->errorString());
        }
    });
}

void MainWindow::onCycleEnabledChanged(bool checked)
{
    m_state.cycleStrategy.enabled = checked;
    if (checked && m_state.cycleStrategy.ipPool.size() >= 2)
        m_state.ipJumpTaskPending = true;
    emit m_state.changed();
}

void MainWindow::onCycleIpPoolChanged(const QString &text)
{
    QStringList ips;
    for (const QString &s : text.split(',')) {
        QString t = s.trimmed();
        if (!t.isEmpty()) ips.append(t);
    }
    m_state.cycleStrategy.ipPool = ips;
    emit m_state.changed();
}

void MainWindow::onCycleGatewayChanged(const QString &text)
{
    m_state.cycleStrategy.gateway = text.trimmed();
    emit m_state.changed();
}

void MainWindow::onCycleIntervalChanged()
{
    m_state.cycleStrategy.activeTime = m_cycleIntervalSpin->value();
    emit m_state.changed();
}

void MainWindow::onCyclePrefixChanged()
{
    m_state.cycleStrategy.prefix = m_cyclePrefixSpin->value();
    emit m_state.changed();
}

void MainWindow::onCycleModeChanged()
{
    m_state.cycleStrategy.mode = m_cycleModeKeep->isChecked() ? 1 : 2;
    emit m_state.changed();
}

void MainWindow::onStateChanged()
{
    // Deferred state updates handled here if needed
}
