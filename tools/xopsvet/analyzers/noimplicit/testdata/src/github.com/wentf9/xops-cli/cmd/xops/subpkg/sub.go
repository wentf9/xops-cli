package main

//xops:buildvar
var buildSub = "dev" // want "禁止声明可变包级 var"

func main() {
	_ = buildSub
}
