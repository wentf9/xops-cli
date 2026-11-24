package vault

//xops:secretuse
func WithMasterKey(fn func(plain []byte) error) error {
	key := []byte("master-key")
	defer clear(key)
	return fn(key)
}
