#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QList>
#include <QTcpServer>
#include <QTcpSocket>
#include <QMap>
#include <QRegularExpression>

// ==================== Data Structures ====================

struct LogEntry {
    QDateTime time;
    QString direction;   // "in" or "out"
    QString path;
    QString summary;
    QJsonObject data;
};

struct JumpInstruction {
    QString sourceIp;
    QString targetIp;
    QString gateway;
    int mode = 1;        // 1=Keep, 2=Force
    int activeTime = 0;
    int agingTime = 2;
    int prefix = 24;

    QString targetIpCidr() const {
        if (targetIp.contains('/')) return targetIp;
        return targetIp + "/" + QString::number(prefix);
    }

    QString sourceIpBare() const {
        if (sourceIp.isEmpty()) return QString();
        if (sourceIp.contains('/')) return sourceIp.split('/').first();
        return sourceIp;
    }

    QJsonObject toJson() const {
        QJsonObject obj;
        obj["source_ip"] = sourceIpBare();
        obj["target_ip"] = targetIpCidr();
        obj["gateway"] = gateway;
        obj["mode"] = mode;
        obj["active_time"] = activeTime;
        obj["aging_time"] = agingTime;
        return obj;
    }

    bool isEmpty() const { return targetIp.isEmpty(); }
};

// ==================== Cycle Strategy ====================

class CycleStrategy {
public:
    bool enabled = false;
    QStringList ipPool;
    QString gateway;
    int mode = 1;
    int activeTime = 30;
    int agingTime = 2;
    int prefix = 24;

    JumpInstruction nextInstruction(const QString &currentAgentIp) {
        if (ipPool.size() < 2) return JumpInstruction();
        int startIdx = ipPool.indexOf(currentAgentIp);
        if (startIdx < 0) startIdx = m_currentIndex;
        int nextIdx = (startIdx + 1) % ipPool.size();
        m_currentIndex = nextIdx;
        JumpInstruction inst;
        inst.targetIp = ipPool[nextIdx];
        inst.gateway = gateway;
        inst.mode = mode;
        inst.activeTime = activeTime;
        inst.agingTime = agingTime;
        inst.prefix = prefix;
        return inst;
    }

private:
    int m_currentIndex = 0;
};

// ==================== MockServerState ====================

class MockServerState : public QObject {
    Q_OBJECT
public:
    explicit MockServerState(QObject *parent = nullptr) : QObject(parent) {}

    bool isRunning = false;
    int port = 8080;
    QString bindAddress = "0.0.0.0";
    QList<LogEntry> logs;
    QList<JumpInstruction> instructionQueue;
    JumpInstruction currentInstruction;
    bool hasCurrentInstruction = false;
    QString lastAgentIp;
    QString lastJumpStatus;
    QString agentUid;
    QString agentMacid;
    QString agentHostName;
    int requestCount = 0;
    bool ipJumpTaskPending = false;
    CycleStrategy cycleStrategy;
    int totalJumpsSent = 0;

    void addLog(const LogEntry &entry) {
        logs.prepend(entry);
        if (logs.size() > 500)
            logs.erase(logs.begin() + 500, logs.end());
        emit changed();
    }

    void queueInstruction(const JumpInstruction &inst) {
        instructionQueue.append(inst);
        if (!hasCurrentInstruction && !instructionQueue.isEmpty()) {
            currentInstruction = instructionQueue.takeFirst();
            hasCurrentInstruction = true;
        }
        if (hasCurrentInstruction)
            ipJumpTaskPending = true;
        emit changed();
    }

    void clearQueue() {
        instructionQueue.clear();
        emit changed();
    }

    void clearLogs() {
        logs.clear();
        emit changed();
    }

signals:
    void changed();
};

// ==================== MockServer ====================

class MockServer : public QObject {
    Q_OBJECT
public:
    explicit MockServer(MockServerState *state, QObject *parent = nullptr);
    ~MockServer();

    void start();
    void stop();

private slots:
    void onNewConnection();

private:
    void handleRequest(QTcpSocket *socket, const QByteArray &data);
    void sendJson(QTcpSocket *socket, const QJsonObject &resp);

    QJsonObject handleAuth(const QJsonObject &req);
    QJsonObject handleGetTask();
    QJsonObject handleGetIpJump();
    QJsonObject handlePutIpJump(const QJsonObject &req);
    QJsonObject handleUploadIp(const QJsonObject &req);
    QJsonObject handleGetToken();
    QJsonObject handleTaskCompletion(const QJsonObject &req);
    QJsonObject handleUploadProcess(const QJsonObject &req);
    QJsonObject handleGetConfig();
    QJsonObject handleCloseTask(const QJsonObject &req);

    QString summarizeRequest(const QString &path, const QJsonObject &req);
    QString summarizeResponse(const QJsonObject &resp);

    MockServerState *m_state;
    QTcpServer *m_server = nullptr;
    QMap<QTcpSocket *, QByteArray> m_buffers;
    QString m_authHeader;
};
