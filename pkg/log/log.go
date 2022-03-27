// package log provides a simple logger with leveled log messages.
//
//   - DebugLevel (highest verbosity)
//   - InfoLevel
//   - WarningLevel
//   - ErrorLevel
//   - FatalLevel (lowest verbosity)
//
// Output is by default written to STDERR.
// A different output can be specified.
// Dates and terminal colors can be turned on.
package log

import (
	"io"
	"log"
	"os"
	"time"
)

type level int

const (
	DebugLevel   level = iota // DebugLevel logs all messages
	InfoLevel                 // InfoLevel logs info messages and and above
	WarningLevel              // WarningLevel logs warning messages and above
	ErrorLevel                // ErrorLevel logs error messages and above
	FatalLevel                // FatalLevel only logs fatal messages
)

const (
	colorDate    = "\033[37m"
	colorDebug   = "\033[95m"
	colorInfo    = "\033[94m"
	colorWarning = "\033[93m"
	colorError   = "\033[91m"
	colorFatal   = "\033[31m"
	colorReset   = "\033[0m"

	tagDebug   = "DEBU"
	tagInfo    = "INFO"
	tagWarning = "WARN"
	tagError   = "ERRO"
	tagFatal   = "FATA"
)

type logger struct {
	log.Logger

	lv    level
	date  bool
	color bool
}

var l logger

func init() {
	l = newLogger(InfoLevel, os.Stderr, false, false)
}

// SetLevel sets the logging level.  Available options: DebugLevel, InfoLevel,
// WarningLevel, ErrorLevel, FatalLevel.  Default: InfoLevel.
func SetLevel(lv level) {
	l.lv = lv
}

// SetOutput sets the logging output to a particular writer. Default: os.Stderr.
func SetOutput(writer io.Writer) {
	l = newLogger(l.lv, writer, l.date, l.color)
}

// SetDate (un)sets date output.  Default: off.
func SetDate(ok bool) {
	l.date = ok
}

// SetColor (un)sets terminal colors.  Default: off.
func SetColor(ok bool) {
	l.color = ok
}

func Debug(format string, v ...interface{}) {
	if l.lv > DebugLevel {
		return
	}

	l.Printf(l.fmt(tagDebug, colorDebug)+format, v...)
}

func Info(format string, v ...interface{}) {
	if l.lv > InfoLevel {
		return
	}

	l.Printf(l.fmt(tagInfo, colorInfo)+format, v...)
}

func Warning(format string, v ...interface{}) {
	if l.lv > WarningLevel {
		return
	}

	l.Printf(l.fmt(tagWarning, colorWarning)+format, v...)
}

func Error(format string, v ...interface{}) {
	if l.lv > ErrorLevel {
		return
	}

	l.Printf(l.fmt(tagError, colorError)+format, v...)
}

func Fatal(format string, v ...interface{}) {
	l.Printf(l.fmt(tagFatal, colorFatal)+format, v...)
	os.Exit(1)
}

func newLogger(lv level, writer io.Writer, date, color bool) logger {
	return logger{
		Logger: *log.New(writer, "", 0),
		lv:     lv,
		date:   date,
		color:  color,
	}
}

func (l *logger) fmt(tag, colorTag string) string {
	date := ""
	if l.date {
		date = time.Now().Format(time.RFC1123) + " "
	}
	if l.color {
		date = colorDate + date + colorReset
		tag = colorTag + tag + colorReset
	}
	tag = "[" + tag + "] "
	return date + tag
}
