package badtime

import "time"

func ValidTime() (time.Duration, time.Time) {
	return 5 * time.Second, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func BadTimeCalls() {
	t := time.Now()            // want "禁止使用非确定性时钟或定时符号 time.Now"
	_ = time.Since(t)          // want "禁止使用非确定性时钟或定时符号 time.Since"
	_ = time.Until(t)          // want "禁止使用非确定性时钟或定时符号 time.Until"
	_ = time.NewTimer(1)       // want "禁止使用非确定性时钟或定时符号 time.NewTimer"
	_ = time.NewTicker(1)      // want "禁止使用非确定性时钟或定时符号 time.NewTicker"
	_ = time.After(1)          // want "禁止使用非确定性时钟或定时符号 time.After"
	time.Sleep(1)              // want "禁止使用非确定性时钟或定时符号 time.Sleep"
	_ = time.AfterFunc(1, nil) // want "禁止使用非确定性时钟或定时符号 time.AfterFunc"
	_ = time.Tick(1)           // want "禁止使用非确定性时钟或定时符号 time.Tick"
}
