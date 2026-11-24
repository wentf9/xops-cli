package pathalg

import "path"

type RemotePath struct {
	raw string
}

func NewRemotePath(s string) RemotePath {
	return RemotePath{raw: path.Clean(s)}
}

func (r RemotePath) String() string {
	return r.raw
}

func (r RemotePath) Join(elem string) RemotePath {
	return RemotePath{raw: path.Join(r.raw, elem)}
}
