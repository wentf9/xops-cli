package ssh

type AuthMethod interface {
	isAuth()
}

type kiAuth struct{}

func (kiAuth) isAuth() {}

type KeyboardInteractiveChallenge func(name, instruction string, questions []string, echos []bool) (answers []string, err error)

func KeyboardInteractive(challenge KeyboardInteractiveChallenge) AuthMethod {
	return kiAuth{}
}
