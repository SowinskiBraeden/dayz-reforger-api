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

// Global file logger (plain)
var FileLogger *log.Logger

// Regex to remove ANSI color codes
var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type cleanWriter struct {
	target io.Writer
}

func (cw cleanWriter) Write(p []byte) (n int, err error) {
	clean := ansi.ReplaceAll(p, []byte(""))
	return cw.target.Write(clean)
}

// InitSessionLogger sets up both console (color) and file logging
func InitSessionLogger() {
	// Ensure /logs directory exists
	_ = os.MkdirAll("logs", 0755)

	filename := time.Now().Format("2006-01-02_15-04-05") + ".log"
	filePath := filepath.Join("logs", filename)

	// File writer with rotation
	rotating := &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    10, // MB
		MaxBackups: 5,
		MaxAge:     14,   // days
		Compress:   true, // compress old logs
	}

	// FileLogger for plain logs (no color)
	FileLogger = log.New(cleanWriter{rotating}, "", log.Ldate|log.Ltime|log.Lshortfile)

	// MultiWriter: writes to stdout (color) + cleanWriter(file)
	multiWriter := io.MultiWriter(os.Stdout, cleanWriter{rotating})

	// Set the default log output (so all log.Printf use both)
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Printf("Logging session to %s\n", filePath)
}
