package main

import "testing"

//xops:buildvar
var testDeclaredBuildVar = "no" // want "禁止声明可变包级 var"

func TestCannotMutateBuildVars(t *testing.T) {
	buildVersion = "override" // want "禁止在运行期修改只读构建变量 buildVersion"
	_ = &buildTime            // want "禁止对只读构建变量 buildTime 取地址"
	for _, buildCommit = range []string{"x"} { // want "禁止在运行期修改只读构建变量 buildCommit"
	}
	_ = testDeclaredBuildVar
}
