#!/bin/bash
### BEGIN INIT INFO
# Provides:          osec
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: OSEC Backend Service
# Description:       Linux Agent Backend Service
### END INIT INFO

PID_FILE=/var/run/osec_backend.pid
BINARY=/opt/osec/MagicArmor_0

start() {
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat $PID_FILE)
        if [ -d "/proc/$OLD_PID" ]; then
            echo "osec is already running (PID: $OLD_PID)"
            return 1
        fi
        rm -f $PID_FILE
    fi

    $BINARY &
    echo $! > $PID_FILE
    echo "osec started (PID: $(cat $PID_FILE))"
    return 0
}

stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "osec is not running"
        return 0
    fi

    PID=$(cat $PID_FILE)
    if [ ! -d "/proc/$PID" ]; then
        rm -f $PID_FILE
        echo "osec is not running"
        return 0
    fi

    kill -15 $PID 2>/dev/null
    sleep 2

    if [ -d "/proc/$PID" ]; then
        echo "osec is protected, cannot be stopped (PID: $PID)"
        return 1
    fi

    rm -f $PID_FILE
    echo "osec stopped"
    return 0
}

status() {
    if [ ! -f "$PID_FILE" ]; then
        echo "osec is not running"
        return 3
    fi

    PID=$(cat $PID_FILE)
    if [ -d "/proc/$PID" ]; then
        echo "osec is running (PID: $PID)"
        return 0
    else
        echo "osec is not running (stale PID file)"
        return 1
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 2
        start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit $?
