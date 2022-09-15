// package log provides a simple logger with leveled log messages.
//
//   - DebugLevel (highest verbosity)
//   - InfoLevel
//   - WarningLevel
//   - ErrorLevel
//   - FatalLevel (lowest verbosity)
//
// Output is written to the default logger.
package log

import (
	"fmt"
	"log"
	"sync/atomic"
)

type level int32

const (
	DebugLevel   level = iota // DebugLevel logs all messages
	InfoLevel                 // InfoLevel logs info messages and and above
	WarningLevel              // WarningLevel logs warning messages and above
	ErrorLevel                // ErrorLevel logs error messages and above
	FatalLevel                // FatalLevel only logs fatal messages
)

const (
	tagDebug   = "DEBU"
	tagInfo    = "INFO"
	tagWarning = "WARN"
	tagError   = "ERRO"
	tagFatal   = "FATA"
)

var currentLevel int32

func init() {
	currentLevel = int32(InfoLevel)
}

// SetLevel sets the logging level.  Available options: DebugLevel, InfoLevel,
// WarningLevel, ErrorLevel, FatalLevel.
func SetLevel(lv level) {
	atomic.StoreInt32(&currentLevel, int32(lv))
}

func SetLevelFromString(levelName string) error {
	switch levelName {
	case "debug":
		SetLevel(DebugLevel)
	case "info":
		SetLevel(InfoLevel)
	case "warning":
		SetLevel(WarningLevel)
	case "error":
		SetLevel(ErrorLevel)
	default:
		return fmt.Errorf("invalid logging level %s", levelName)
	}
	return nil
}

func isEnabled(lv level) bool {
	return level(atomic.LoadInt32(&currentLevel)) <= lv
}

func Debug(format string, v ...interface{}) {
	if isEnabled(DebugLevel) {
		log.Printf("["+tagDebug+"] "+format, v...)
	}
}

func Info(format string, v ...interface{}) {
	if isEnabled(InfoLevel) {
		log.Printf("["+tagInfo+"] "+format, v...)
	}
}

func Warning(format string, v ...interface{}) {
	if isEnabled(WarningLevel) {
		log.Printf("["+tagWarning+"] "+format, v...)
	}
}

func Error(format string, v ...interface{}) {
	if isEnabled(ErrorLevel) {
		log.Printf("["+tagError+"] "+format, v...)
	}
}

func Fatal(format string, v ...interface{}) {
	log.Fatalf("["+tagFatal+"] "+format, v...)
}
