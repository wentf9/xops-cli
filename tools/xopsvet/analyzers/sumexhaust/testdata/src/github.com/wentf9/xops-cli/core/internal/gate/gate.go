package gate

import "errors"

type GateVerdict interface {
	sealedVerdict()
}

type VerdictReject struct{}

func (*VerdictReject) sealedVerdict() {}

type VerdictApprove struct{}

func (*VerdictApprove) sealedVerdict() {}

func checkGateVerdict(v GateVerdict) error {
	switch v.(type) {
	case *VerdictReject:
		return errors.New("rejected")
	case *VerdictApprove:
		return nil
	default:
		return errors.New("fail closed")
	}
}

func checkGateVerdictFailOpen(v GateVerdict) (GateVerdict, error) {
	switch v.(type) {
	case *VerdictReject:
		return &VerdictReject{}, nil
	case *VerdictApprove:
		return &VerdictApprove{}, nil
	default:
		return &VerdictApprove{}, nil // want "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）"
	}
}
