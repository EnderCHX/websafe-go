package log

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Logger *zap.Logger

var (
	cWhiteBlue    = "\033[1;37;44m"
	cWhiteRed     = "\033[1;37;41m"
	cWhiteYellow  = "\033[1;37;43m"
	cWhiteBlack   = "\033[1;37;40m"
	cWhiteGreen   = "\033[1;37;42m"
	cWhiteCyan    = "\033[1;37;46m"
	cWhiteMagenta = "\033[1;37;45m"
	cEnd          = "\033[0m"

	cBlue    = "\033[1;34m"
	cRed     = "\033[1;31m"
	cGreen   = "\033[1;32m"
	cCyan    = "\033[1;36m"
	cMagenta = "\033[1;35m"
	cYellow  = "\033[1;33m"
	cBlack   = "\033[1;30m"
	cWhite   = "\033[1;37m"
)

type Encoder struct {
	zapcore.Encoder
	separator string
	title     string
	color     bool
}

func (e *Encoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	buf := buffer.NewPool().Get()

	ifColor := func(s, c string) string {
		if !e.color {
			return s
		}
		return c + s + cEnd
	}

	// 标题
	buf.AppendString(ifColor(e.title, cBlue))
	buf.AppendString(ifColor(e.separator, cYellow))

	// 时间
	buf.AppendString(ifColor(entry.Time.Format("2006-01-02 15:04:05"), cGreen))
	buf.AppendString(ifColor(e.separator, cYellow))

	// 日志级别
	if entry.Level == zapcore.DebugLevel {
		buf.AppendString(ifColor("[DEBUG]", cBlack))
	} else if entry.Level == zapcore.InfoLevel {
		buf.AppendString(ifColor("[INFO] ", cBlue))
	} else if entry.Level == zapcore.WarnLevel {
		buf.AppendString(ifColor("[WARN] ", cYellow))
	} else if entry.Level == zapcore.ErrorLevel {
		buf.AppendString(ifColor("[ERROR]", cRed))
	}
	buf.AppendString(ifColor(e.separator, cYellow))

	// 调用者
	if entry.Caller.Defined {
		buf.AppendString(entry.Caller.TrimmedPath())
		buf.AppendString(ifColor(e.separator, cYellow))
	}

	// 消息
	buf.AppendString(ifColor(entry.Message, cCyan))

	// 字段
	for _, field := range fields {
		buf.AppendString(ifColor(e.separator, cYellow))
		buf.AppendString(ifColor(field.Key, cMagenta))
		buf.AppendString(ifColor("=", cMagenta))
		if field.Type == 15 {
			buf.AppendString(ifColor(field.String, cMagenta))
		} else if field.Type == 11 {
			buf.AppendString(ifColor(fmt.Sprintf("%v", field.Integer), cMagenta))
		} else {
			buf.AppendString(ifColor("nil", cMagenta))
		}
		buf.AppendString(ifColor(" ", cMagenta))
	}

	buf.AppendString("\n")
	return buf, nil
}
func Setup(path, loglevel string) {
	Logger = NewLogger(path, loglevel)
}

func NewLogger(path, loglevel string) *zap.Logger {
	var level zap.AtomicLevel

	if loglevel == "debug" {
		level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else if loglevel == "info" {
		level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	encoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    "func",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     customTimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})

	lumberjackLogger := &lumberjack.Logger{
		Filename:   path,
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     28,
	}

	core := zapcore.NewTee(
		zapcore.NewCore(
			&Encoder{Encoder: encoder, separator: "|", title: "[BLOG]"},
			zapcore.AddSync(lumberjackLogger),
			level,
		),
		zapcore.NewCore(
			&Encoder{Encoder: encoder, separator: "", title: "[BLOG]", color: true},
			zapcore.AddSync(os.Stdout),
			level,
		),
	)

	newLogger := zap.New(core)
	defer newLogger.Sync()

	newLogger.Info("日志初始化成功: " + path)
	return newLogger
}

func GetLogger() *zap.Logger {
	return Logger
}
func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05"))
}
