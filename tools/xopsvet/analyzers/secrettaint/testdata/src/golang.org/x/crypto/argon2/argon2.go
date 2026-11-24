package argon2

func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return make([]byte, keyLen)
}
