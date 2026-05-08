#include "mockserver.h"
#include <QHostAddress>

MockServer::MockServer(MockServerState *state, QObject *parent)
    : QObject(parent), m_state(state)
{
}

MockServer::~MockServer()
{
    stop();
}

void MockServer::start()
{
    if (m_state->isRunning) return;

    m_server = new QTcpServer(this);
    QHostAddress addr(m_state->bindAddress);
    if (!m_server->listen(addr, m_state->port)) {
        LogEntry e;
        e.time = QDateTime::currentDateTime();
        e.direction = "out";
        e.summary = "Failed to start server: " + m_server->errorString();
        m_state->addLog(e);
        return;
    }

    m_state->isRunning = true;
    LogEntry e;
    e.time = QDateTime::currentDateTime();
    e.direction = "out";
    e.summary = "Server started on " + m_state->bindAddress + ":" + QString::number(m_state->port);
    m_state->addLog(e);

    connect(m_server, &QTcpServer::newConnection, this, &MockServer::onNewConnection);
}

void MockServer::stop()
{
    if (m_server) {
        m_server->close();
        m_server->deleteLater();
        m_server = nullptr;
    }
    m_buffers.clear();
    m_state->isRunning = false;

    LogEntry e;
    e.time = QDateTime::currentDateTime();
    e.direction = "out";
    e.summary = "Server stopped";
    m_state->addLog(e);
}

void MockServer::onNewConnection()
{
    while (m_server->hasPendingConnections()) {
        QTcpSocket *socket = m_server->nextPendingConnection();

        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
            m_buffers[socket].append(socket->readAll());
            QByteArray &buf = m_buffers[socket];

            int headerEnd = buf.indexOf("\r\n\r\n");
            if (headerEnd < 0) return;

            // Parse Content-Length
            QByteArray headers = buf.left(headerEnd);
            int contentLength = 0;
            for (const QByteArray &line : headers.split('\n')) {
                if (line.trimmed().toLower().startsWith("content-length:")) {
                    int colonIdx = line.indexOf(':');
                    contentLength = line.mid(colonIdx + 1).trimmed().toInt();
                    break;
                }
            }

            int bodyStart = headerEnd + 4;
            if (buf.size() < bodyStart + contentLength) return;

            // Complete request
            QByteArray requestData = buf.left(bodyStart + contentLength);
            buf.remove(0, bodyStart + contentLength);
            handleRequest(socket, requestData);
        });

        connect(socket, &QTcpSocket::disconnected, this, [this, socket]() {
            m_buffers.remove(socket);
            socket->deleteLater();
        });
    }
}

void MockServer::handleRequest(QTcpSocket *socket, const QByteArray &data)
{
    int headerEnd = data.indexOf("\r\n\r\n");
    QByteArray headerBlock = data.left(headerEnd);
    QByteArray body = data.mid(headerEnd + 4);

    QList<QByteArray> headerLines = headerBlock.split('\n');
    QString firstLine = headerLines.first().trimmed();
    QStringList parts = firstLine.split(' ');
    QString method = parts.value(0);
    QString path = parts.value(1);

    m_authHeader.clear();
    for (const QByteArray &line : headerLines) {
        if (line.trimmed().toLower().startsWith("authorization:")) {
            int colonIdx = line.indexOf(':');
            m_authHeader = line.mid(colonIdx + 1).trimmed();
            break;
        }
    }

    QJsonObject reqData;
    if (!body.isEmpty()) {
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(body, &err);
        if (err.error == QJsonParseError::NoError && doc.isObject())
            reqData = doc.object();
    }

    m_state->requestCount++;

    QJsonObject response;
    if (path == "/v1/auth")
        response = handleAuth(reqData);
    else if (path == "/v1/gettask")
        response = handleGetTask();
    else if (path == "/v1/getIpJump")
        response = handleGetIpJump();
    else if (path == "/v1/putIpJump")
        response = handlePutIpJump(reqData);
    else if (path == "/v1/uploadIp")
        response = handleUploadIp(reqData);
    else if (path == "/v1/getToken")
        response = handleGetToken();
    else if (path == "/v1/reportTaskCompletion")
        response = handleTaskCompletion(reqData);
    else if (path == "/v1/uploadproc" || path == "/v1/upload/suffix/exe")
        response = handleUploadProcess(reqData);
    else if (path == "/v1/getconf" || path == "/v1/getprotect")
        response = handleGetConfig();
    else if (path == "/v1/closetask")
        response = handleCloseTask(reqData);
    else
        response = QJsonObject{{"code", "000000"}, {"msg", "success"}, {"data", QJsonObject{}}};

    sendJson(socket, response);

    LogEntry entry;
    entry.time = QDateTime::currentDateTime();
    entry.direction = "in";
    entry.path = path;
    QString authTag = m_authHeader.isEmpty() ? "" : " [token]";
    entry.summary = method + " " + path + authTag +
                    "\n  >> " + summarizeRequest(path, reqData) +
                    "\n  << " + summarizeResponse(response);
    QJsonObject logData;
    logData["request"] = reqData;
    logData["response"] = response;
    entry.data = logData;
    m_state->addLog(entry);
}

void MockServer::sendJson(QTcpSocket *socket, const QJsonObject &resp)
{
    QByteArray body = QJsonDocument(resp).toJson(QJsonDocument::Compact);
    QByteArray response = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
                          "\r\n";
    response += body;
    socket->write(response);
    socket->flush();
    socket->disconnectFromHost();
}

// ==================== Route Handlers ====================

QJsonObject MockServer::handleAuth(const QJsonObject &req)
{
    m_state->agentUid = req.value("uid").toString();
    m_state->agentMacid = req.value("macid").toString();
    m_state->agentHostName = req.value("host_name").toString();
    QString ipList = req.value("ip").toString();
    if (!ipList.isEmpty())
        m_state->lastAgentIp = ipList.split(',').first().trimmed();

    QJsonObject resp;
    resp["code"] = "000000";
    resp["msg"] = "success";
    QJsonObject data;
    data["token"] = "mock-token-" + QString::number(QDateTime::currentMSecsSinceEpoch());
    resp["data"] = data;
    return resp;
}

QJsonObject MockServer::handleGetTask()
{
    QJsonArray taskList;
    if (m_state->ipJumpTaskPending)
        taskList.append(37);

    QJsonObject resp;
    resp["code"] = "000000";
    resp["msg"] = "success";
    QJsonObject data;
    data["tasklist"] = taskList;
    resp["data"] = data;
    return resp;
}

QJsonObject MockServer::handleGetIpJump()
{
    if (m_state->hasCurrentInstruction) {
        JumpInstruction inst = m_state->currentInstruction;
        m_state->currentInstruction = JumpInstruction();
        m_state->hasCurrentInstruction = false;
        m_state->ipJumpTaskPending = false;
        m_state->totalJumpsSent++;

        if (!m_state->instructionQueue.isEmpty()) {
            m_state->currentInstruction = m_state->instructionQueue.takeFirst();
            m_state->hasCurrentInstruction = true;
            m_state->ipJumpTaskPending = true;
        } else if (m_state->cycleStrategy.enabled) {
            QString nextTarget = inst.targetIp.contains('/')
                ? inst.targetIp.split('/').first()
                : inst.targetIp;
            JumpInstruction next = m_state->cycleStrategy.nextInstruction(nextTarget);
            if (!next.isEmpty()) {
                m_state->currentInstruction = next;
                m_state->hasCurrentInstruction = true;
                m_state->ipJumpTaskPending = true;
            }
        }

        LogEntry e;
        e.time = QDateTime::currentDateTime();
        e.direction = "out";
        e.path = "/v1/getIpJump";
        e.summary = "QUEUE: " + QString::number(m_state->instructionQueue.size()) + " remaining";
        m_state->addLog(e);

        QJsonObject resp;
        resp["code"] = "000000";
        resp["msg"] = "success";
        resp["data"] = inst.toJson();
        return resp;
    }

    if (m_state->cycleStrategy.enabled) {
        JumpInstruction inst = m_state->cycleStrategy.nextInstruction(m_state->lastAgentIp);
        if (!inst.isEmpty()) {
            m_state->totalJumpsSent++;
            JumpInstruction next = m_state->cycleStrategy.nextInstruction(inst.targetIp);
            if (!next.isEmpty()) {
                m_state->currentInstruction = next;
                m_state->hasCurrentInstruction = true;
                m_state->ipJumpTaskPending = true;
            }
            QJsonObject resp;
            resp["code"] = "000000";
            resp["msg"] = "success";
            resp["data"] = inst.toJson();
            return resp;
        }
    }

    QString reason = m_state->cycleStrategy.enabled
        ? "cycle enabled but ipPool has only " + QString::number(m_state->cycleStrategy.ipPool.size()) +
          " IPs (need >=2), lastAgentIp=" + m_state->lastAgentIp
        : "no instruction queued and cycle not enabled";

    LogEntry e;
    e.time = QDateTime::currentDateTime();
    e.direction = "out";
    e.path = "/v1/getIpJump";
    e.summary = "EMPTY: " + reason;
    m_state->addLog(e);

    QJsonObject emptyInst;
    emptyInst["source_ip"] = "";
    emptyInst["target_ip"] = "";
    emptyInst["gateway"] = "";
    emptyInst["active_time"] = 0;
    emptyInst["aging_time"] = 2;
    emptyInst["mode"] = 1;
    QJsonObject resp;
    resp["code"] = "000000";
    resp["msg"] = "success";
    resp["data"] = emptyInst;
    return resp;
}

QJsonObject MockServer::handlePutIpJump(const QJsonObject &req)
{
    int status = req.value("status").toInt();
    QString srcIp = req.value("source_ip").toString();
    QString tgtIp = req.value("target_ip").toString();
    QString agentIp = req.value("agent_ip").toString();
    QString reason = req.value("reason").toString();

    m_state->lastJumpStatus = (status == 1) ? "SUCCESS" : "FAILED";
    if (!agentIp.isEmpty())
        m_state->lastAgentIp = agentIp.split(',').first().trimmed();

    LogEntry e;
    e.time = QDateTime::currentDateTime();
    e.direction = "in";
    e.path = "/v1/putIpJump";
    e.summary = "Jump result: status=" + QString::number(status) +
                ", src=" + srcIp + ", tgt=" + tgtIp +
                ", agent=" + agentIp + ", reason=" + reason;
    e.data = req;
    m_state->addLog(e);

    return QJsonObject{{"code", "000000"}, {"msg", "success"}};
}

QJsonObject MockServer::handleUploadIp(const QJsonObject &req)
{
    QString ipList = req.value("ip").toString();
    if (!ipList.isEmpty()) {
        QStringList ips = ipList.split(',');
        if (!ips.isEmpty()) {
            m_state->lastAgentIp = ips.first().trimmed();
            LogEntry e;
            e.time = QDateTime::currentDateTime();
            e.direction = "in";
            e.path = "/v1/uploadIp";
            e.summary = "IP report: logical_primary=" + ips.first() + ", all=" + ipList;
            e.data = req;
            m_state->addLog(e);
        }
    }
    return QJsonObject{{"code", "000000"}, {"msg", "success"}};
}

QJsonObject MockServer::handleGetToken()
{
    QJsonObject resp;
    resp["code"] = "000000";
    resp["msg"] = "success";
    QJsonObject data;
    data["token"] = "mock-token-" + QString::number(QDateTime::currentMSecsSinceEpoch());
    resp["data"] = data;
    return resp;
}

QJsonObject MockServer::handleTaskCompletion(const QJsonObject &)
{
    return QJsonObject{{"code", "000000"}, {"msg", "success"}};
}

QJsonObject MockServer::handleUploadProcess(const QJsonObject &)
{
    return QJsonObject{{"code", "000000"}, {"msg", "success"}};
}

QJsonObject MockServer::handleGetConfig()
{
    return QJsonObject{{"code", "000000"}, {"msg", "success"}, {"data", QJsonObject{}}};
}

QJsonObject MockServer::handleCloseTask(const QJsonObject &)
{
    return QJsonObject{{"code", "000000"}, {"msg", "success"}};
}

// ==================== Summaries ====================

QString MockServer::summarizeRequest(const QString &path, const QJsonObject &req)
{
    if (path == "/v1/auth")
        return "AUTH uid=" + req.value("uid").toString("?") +
               ", host=" + req.value("host_name").toString("?") +
               ", ip=" + req.value("ip").toString("?");
    if (path == "/v1/gettask")
        return "GET-TASK (agent polling for task list)";
    if (path == "/v1/getIpJump")
        return "GET-IP-JUMP (agent fetching jump instruction)";
    if (path == "/v1/putIpJump")
        return "PUT-IP-JUMP status=" + QString::number(req.value("status").toInt()) +
               ", src=" + req.value("source_ip").toString() +
               ", tgt=" + req.value("target_ip").toString() +
               ", agent_ip=" + req.value("agent_ip").toString();
    if (path == "/v1/uploadIp")
        return "UPLOAD-IP: " + req.value("ip").toString();
    if (path == "/v1/reportTaskCompletion")
        return "TASK-COMPLETE";
    if (path == "/v1/closetask")
        return "CLOSE-TASK";
    return path + " (body keys=" +
           QStringList(req.keys()).join(',') + ")";
}

QString MockServer::summarizeResponse(const QJsonObject &resp)
{
    QString code = resp.value("code").toString();
    QJsonObject data = resp.value("data").toObject();
    if (data.contains("tasklist"))
        return "code=" + code + ", tasklist=" +
               QString(QJsonDocument(data["tasklist"].toArray()).toJson(QJsonDocument::Compact));
    if (data.contains("target_ip"))
        return "code=" + code + ", target=" + data["target_ip"].toString() +
               ", mode=" + QString::number(data["mode"].toInt()) +
               ", active=" + QString::number(data["active_time"].toInt()) + "s";
    if (data.contains("token")) {
        QString t = data["token"].toString();
        return "code=" + code + ", token=" +
               (t.length() > 20 ? t.left(20) + "..." : t);
    }
    return "code=" + code;
}
