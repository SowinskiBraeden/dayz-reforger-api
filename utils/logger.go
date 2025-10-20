package utils

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	FileLogger  *log.Logger
	ErrorLogger *log.Logger
	ansi        = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	logDir      = "logs"
	loggerMutex sync.Mutex
)

var LogLevel = LogWarnLevel // default

const (
	LogErrorLevel = iota
	LogWarnLevel
	LogInfoLevel
	LogDebugLevel
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
)

// cleanWriter strips colors for file logs
type cleanWriter struct{ target io.Writer }

func (cw cleanWriter) Write(p []byte) (n int, err error) {
	clean := ansi.ReplaceAll(p, []byte(""))
	return cw.target.Write(clean)
}

// dualWriter sends logs to console and files; duplicates error lines to error logs
type dualWriter struct {
	consoleWriter io.Writer
	fileWriter    io.Writer
	errorWriter   io.Writer
}

func (dw dualWriter) Write(p []byte) (n int, err error) {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()

	// Always print to console
	_, _ = dw.consoleWriter.Write(p)

	// Always write to main log
	n, err = dw.fileWriter.Write(p)

	// If the message looks like an error, also write to the error log
	lower := bytes.ToLower(p)
	if bytes.Contains(lower, []byte("error")) {
		_, _ = dw.errorWriter.Write(p)
	}
	return
}

func InitSessionLogger() {
	_ = os.MkdirAll(logDir, 0755)

	setupLogger()
	go dailyLogRolloverWatcher()
}

func setupLogger() {
	mainName := time.Now().Format("2006-01-02_15-04-05") + ".log"
	mainPath := filepath.Join(logDir, mainName)

	errorName := "errors_" + time.Now().Format("2006-01-02") + ".log"
	errorPath := filepath.Join(logDir, errorName)

	mainRotating := &lumberjack.Logger{
		Filename:   mainPath,
		MaxSize:    10,
		MaxBackups: 14,
		MaxAge:     7,
		Compress:   true,
	}

	errorRotating := &lumberjack.Logger{
		Filename:   errorPath,
		MaxSize:    5,
		MaxBackups: 30,
		MaxAge:     30,
		Compress:   true,
	}

	FileLogger = log.New(cleanWriter{mainRotating}, "", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(cleanWriter{errorRotating}, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	multi := dualWriter{
		consoleWriter: os.Stdout,
		fileWriter:    cleanWriter{mainRotating},
		errorWriter:   cleanWriter{errorRotating},
	}

	log.SetOutput(multi)
	log.SetFlags(log.Ldate | log.Ltime)

	LogInfo(fmt.Sprintf("Logging session to %s (errors to %s)", mainPath, errorPath))
}

func dailyLogRolloverWatcher() {
	for {
		now := time.Now()
		nextMidnight := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
		time.Sleep(time.Until(nextMidnight))
		setupLogger()
	}
}

func LogInfo(msg string, v ...any) {
	if LogLevel < LogInfoLevel {
		return
	}
	log.Printf(colorCyan+"[INFO]  "+colorReset+msg, v...)
}

func LogSuccess(msg string, v ...any) {
	log.Printf(colorGreen+"[ OK ]  "+colorReset+msg, v...)
}

func LogWarn(msg string, v ...any) {
	log.Printf(colorYellow+"[WARN]  "+colorReset+msg, v...)
}

func LogError(msg string, v ...any) {
	log.Printf(colorRed+"[ERROR] "+colorReset+msg, v...)
}

func LogDebug(msg string, v ...any) {
	if LogLevel < LogDebugLevel {
		return
	}
	log.Printf(colorCyan+"[DEBUG] "+colorReset+msg, v...)
}
