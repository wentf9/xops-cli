package windows

type Handle uintptr

const (
	OPEN_EXISTING   = 3
	SE_KERNEL_OBJECT = 6
)

func CreateFile(name *uint16, access, mode uint32, sa *byte, createmode, attrs uint32, templatefile int32) (Handle, error) {
	return 0, nil
}
func GetSecurityInfo(handle Handle, objectType, securityInformation uint32) (uintptr, error) {
	return 0, nil
}
