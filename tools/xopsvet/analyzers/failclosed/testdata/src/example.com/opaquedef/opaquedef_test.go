package opaquedef

func testSamePkgConstructionAllowed() {
	_ = Token{id: "whitebox"}
	_ = new(Token)
	_ = OpID("whitebox")
}
