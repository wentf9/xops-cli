package badtime

import "time"

func BadTimezoneAndLocal(t time.Time) {
	_, _ = time.LoadLocation("UTC") // want "禁止使用非确定性时钟或定时符号 time.LoadLocation"
	_ = time.Local                  // want "禁止使用非确定性时钟或定时符号 time.Local"
	_ = t.Local()                   // want "禁止使用非确定性本地时区方法 \\(time\\.Time\\)\\.Local"
}
