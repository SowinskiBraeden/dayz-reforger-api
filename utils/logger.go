package utils

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	FileLogger *log.Logger
	ansi       = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

type cleanWriter struct{ target io.Writer }

func (cw cleanWriter) Write(p []byte) (n int, err error) {
	clean := ansi.ReplaceAll(p, []byte(""))
	return cw.target.Write(clean)
}

func InitSessionLogger() {
	logDir := "logs"
	_ = os.MkdirAll(logDir, 0755)

	setupLogger(logDir)                // initial setup
	go dailyLogRolloverWatcher(logDir) // handle rollover at midnight
}

func setupLogger(logDir string) {
	filename := time.Now().Format("2006-01-02_15-04-05") + ".log"
	filePath := filepath.Join(logDir, filename)

	rotating := &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    10, // MB per file before rotation
		MaxBackups: 14,
		MaxAge:     7, // days
		Compress:   true,
	}

	FileLogger = log.New(cleanWriter{rotating}, "", log.Ldate|log.Ltime|log.Lshortfile)
	multiWriter := io.MultiWriter(os.Stdout, cleanWriter{rotating})
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Printf("Logging session to %s\n", filePath)
}

func dailyLogRolloverWatcher(logDir string) {
	for {
		// Sleep until midnight
		now := time.Now()
		nextMidnight := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
		time.Sleep(time.Until(nextMidnight))

		// Recreate the logger with a new filename
		setupLogger(logDir)
	}
}
