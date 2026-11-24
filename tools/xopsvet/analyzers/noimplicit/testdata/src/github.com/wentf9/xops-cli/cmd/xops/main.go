package main

import "fmt"

const defaultCommit = "none"

//xops:buildvar
var buildVersion = "dev"

//xops:buildvar
var buildCommit = defaultCommit

//xops:buildvar
var buildTime string

var buildRev = "0" //xops:buildvar

var (
	//xops:buildvar
	buildChannel = "stable"
	badInBlock   = "nope" // want "禁止声明可变包级 var"
)

//xops:buildvar
var (
	badMultiA = "a" // want "禁止声明可变包级 var"
	badMultiB = "b" // want "禁止声明可变包级 var"
)

//xops:buildvar
var BuildExported = "x" // want "禁止声明可变包级 var"

//xops:buildvar
var buildNum = 1 // want "禁止声明可变包级 var"

type customStr string

//xops:buildvar
var buildNamed customStr = "x" // want "禁止声明可变包级 var"

func dynamicVersion() string { return "dyn" }

//xops:buildvar
var buildDyn = dynamicVersion() // want "禁止声明可变包级 var"

//xops:buildvar
var buildPairA, buildPairB = "a", "b" // want "禁止声明可变包级 var"

// buildVars 绝不混入 sentinels，不能作为 fmt.Errorf 参数声明哨兵错误。
var ErrBuildWrap = fmt.Errorf("version=%s", buildVersion) // want "禁止声明可变包级 var"

func main() {
	//nolint:errcheck // want "白名单包外禁止使用行内 //nolint"
	_, _ = fmt.Println(buildVersion, buildCommit, buildTime, buildRev, buildChannel)
}

func mutateBuildVars() {
	buildVersion = "tampered"  // want "禁止在运行期修改只读构建变量 buildVersion"
	buildVersion += "-dirty"   // want "禁止在运行期修改只读构建变量 buildVersion"
	p := &buildCommit          // want "禁止对只读构建变量 buildCommit 取地址"
	_ = p
	for _, buildTime = range []string{"now"} { // want "禁止在运行期修改只读构建变量 buildTime"
	}
	for buildRev = range map[string]int{} { // want "禁止在运行期修改只读构建变量 buildRev"
	}
}
