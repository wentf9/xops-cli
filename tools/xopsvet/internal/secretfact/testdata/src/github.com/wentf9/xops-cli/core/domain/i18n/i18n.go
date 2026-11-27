package i18n

// 汇点与 //xops:syncclosure 严格互斥：FormatTemplate 属于 SinkError，不得导出 SyncFact。
//
//xops:syncclosure
func FormatTemplate(tmpl string, resolve func(string) (string, bool)) string {
	return tmpl
}

// 非汇点函数仍正常导出 SyncFact。
//
//xops:syncclosure
func RunNonSink(fn func() error) error { // want RunNonSink:"syncclosure"
	return fn()
}
