package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
)

type feedParseLog struct {
	path, header, id string
	log              io.Writer
	loc              *time.Location
	file             *os.File
	failed           bool
}

func (l *feedParseLog) append(record feedparse.FailRecord) {
	if l.path == "" || l.failed {
		return
	}
	if l.file == nil {
		file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			l.warn()
			return
		}
		l.file = file
	}
	// Line and Raw already carry the parser's legacy null and line-ending rules.
	_, err := fmt.Fprintf(l.file, "%s,%s,%s,%s,%d\n", time.Now().In(l.loc).Format("2006-01-02 15:04:05"),
		l.header, record.Line, record.Raw, record.LineNo)
	if err != nil {
		l.warn()
	}
}

func (l *feedParseLog) warn() {
	if l.failed {
		return
	}
	l.failed = true
	if l.log != nil {
		fmt.Fprintf(l.log, "feed %s: warning: detailed parse log append failed\n", l.id)
	}
}

func (l *feedParseLog) close() {
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			l.warn()
		}
	}
}
