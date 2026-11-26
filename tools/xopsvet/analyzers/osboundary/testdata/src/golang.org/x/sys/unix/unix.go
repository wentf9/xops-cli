package unix

const (
	O_RDONLY   = 0x0
	O_RDWR     = 0x2
	O_CREAT    = 0x40
	O_NONBLOCK = 0x800
	O_CLOEXEC  = 0x80000
)

type Stat_t struct{}

func Open(path string, mode int, perm uint32) (int, error)             { return 0, nil }
func Openat(dirfd int, path string, flags int, mode uint32) (int, error) { return 0, nil }
func Fstat(fd int, stat *Stat_t) error                                 { return nil }
