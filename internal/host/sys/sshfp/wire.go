package sshfp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/ports"
)

type parsedDNSRecord struct {
	name  string
	rtype uint16
	class uint16
	rdata []byte
}

type parsedDNSMessage struct {
	id        uint16
	qr        bool
	truncated bool
	ad        bool
	rcode     uint16
	answers   []parsedDNSRecord
}

func buildSSHFPQuery(txid uint16, qname string) ([]byte, error) {
	wireName, err := encodeDNSName(qname)
	if err != nil {
		return nil, err
	}
	// Header(12) + QNAME + QTYPE(2) + QCLASS(2) + OPT RR(11: root 0 + type 41 + payload 1232 + extRcode/ver/DO + rdlen 0)
	msg := make([]byte, 0, dnsHeaderBytes+len(wireName)+4+11)
	var hdr [dnsHeaderBytes]byte
	binary.BigEndian.PutUint16(hdr[0:2], txid)
	binary.BigEndian.PutUint16(hdr[2:4], dnsFlagRD|dnsFlagAD)
	binary.BigEndian.PutUint16(hdr[4:6], 1)   // QDCOUNT = 1
	binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT = 1 (EDNS0 OPT)
	msg = append(msg, hdr[:]...)
	msg = append(msg, wireName...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeSSHFP)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	// EDNS0 OPT pseudo-RR (RFC 6891, DO=1 requesting DNSSEC awareness)
	msg = append(msg, 0x00)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeOPT)
	msg = binary.BigEndian.AppendUint16(msg, dnsEDNSUDPPayload)
	msg = append(msg, 0x00, 0x00) // extended RCODE = 0, version = 0
	msg = binary.BigEndian.AppendUint16(msg, dnsEDNSDOBit)
	msg = binary.BigEndian.AppendUint16(msg, 0) // RDLENGTH = 0
	return msg, nil
}

func encodeDNSName(name string) ([]byte, error) {
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if trimmed == "" || len(trimmed) > 253 {
		return nil, fmt.Errorf("%w: DNS 查询域名长度非法", ports.ErrInvalidArgument)
	}
	labels := strings.Split(trimmed, ".")
	out := make([]byte, 0, len(trimmed)+2)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("%w: DNS 标签长度非法", ports.ErrInvalidArgument)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0x00)
	return out, nil
}

func parseDNSResponse(raw []byte, wantID uint16, wantQName string) (parsedDNSMessage, error) {
	if len(raw) < dnsHeaderBytes {
		return parsedDNSMessage{}, fmt.Errorf("%w: DNS 应答长度不足 12 字节", ports.ErrCorruptData)
	}
	id := binary.BigEndian.Uint16(raw[0:2])
	flags := binary.BigEndian.Uint16(raw[2:4])
	qdCount := int(binary.BigEndian.Uint16(raw[4:6]))
	anCount := int(binary.BigEndian.Uint16(raw[6:8]))
	if id != wantID || flags&dnsFlagQR == 0 {
		return parsedDNSMessage{}, fmt.Errorf("%w: DNS 应答事务 ID 或 QR 标志不匹配", ports.ErrCorruptData)
	}
	msg := parsedDNSMessage{
		id:        id,
		qr:        true,
		truncated: flags&dnsFlagTC != 0,
		ad:        flags&dnsFlagAD != 0,
		rcode:     flags & dnsRcodeMask,
	}
	if msg.truncated {
		return msg, nil
	}
	off, err := verifyDNSQuestion(raw, dnsHeaderBytes, qdCount, wantQName)
	if err != nil {
		return parsedDNSMessage{}, err
	}
	answers, err := parseDNSAnswers(raw, off, anCount)
	if err != nil {
		return parsedDNSMessage{}, err
	}
	msg.answers = answers
	return msg, nil
}

// verifyDNSQuestion 按 RFC 5452 §9.1 核验 QDCOUNT==1 且响应 Question 的 (QNAME, QTYPE, QCLASS) 与请求一致。
func verifyDNSQuestion(raw []byte, off, count int, wantQName string) (int, error) {
	if count != 1 {
		return 0, fmt.Errorf("%w: DNS 应答 QDCOUNT=%d 不等于 1", ports.ErrCorruptData, count)
	}
	next, gotName, err := decodeDNSName(raw, off)
	if err != nil {
		return 0, err
	}
	if next+4 > len(raw) {
		return 0, fmt.Errorf("%w: DNS Question 段截断", ports.ErrCorruptData)
	}
	qtype := binary.BigEndian.Uint16(raw[next : next+2])
	qclass := binary.BigEndian.Uint16(raw[next+2 : next+4])
	want := strings.ToLower(strings.TrimSuffix(wantQName, "."))
	if gotName != want || qtype != dnsTypeSSHFP || qclass != dnsClassIN {
		return 0, fmt.Errorf("%w: DNS Question 段 (%q, %d, %d) 与查询不匹配", ports.ErrCorruptData, gotName, qtype, qclass)
	}
	return next + 4, nil
}

func parseDNSAnswers(raw []byte, off, count int) ([]parsedDNSRecord, error) {
	records := make([]parsedDNSRecord, 0, count)
	for range count {
		next, name, err := decodeDNSName(raw, off)
		if err != nil {
			return nil, err
		}
		if next+10 > len(raw) {
			return nil, fmt.Errorf("%w: DNS Answer 头部截断", ports.ErrCorruptData)
		}
		rtype := binary.BigEndian.Uint16(raw[next : next+2])
		rclass := binary.BigEndian.Uint16(raw[next+2 : next+4])
		rdLen := int(binary.BigEndian.Uint16(raw[next+8 : next+10]))
		dataStart := next + 10
		if dataStart+rdLen > len(raw) {
			return nil, fmt.Errorf("%w: DNS Answer RDATA 越界", ports.ErrCorruptData)
		}
		rdata := raw[dataStart : dataStart+rdLen]
		if rtype == dnsTypeCNAME {
			cEnd, target, cErr := decodeDNSName(raw, dataStart)
			if cErr != nil || cEnd != dataStart+rdLen {
				return nil, fmt.Errorf("%w: DNS CNAME RDATA 长度或名称边界非法", ports.ErrCorruptData)
			}
			rdata = []byte(target)
		}
		records = append(records, parsedDNSRecord{
			name:  name,
			rtype: rtype,
			class: rclass,
			rdata: rdata,
		})
		off = dataStart + rdLen
	}
	return records, nil
}

func decodeDNSName(raw []byte, start int) (nextOff int, name string, err error) {
	var labels []string
	cur, jumped, jumps, octets := start, false, 0, 1
	for {
		if cur >= len(raw) {
			return 0, "", fmt.Errorf("%w: DNS 名称解码越界", ports.ErrCorruptData)
		}
		length := int(raw[cur])
		if length == 0 {
			return finishDNSName(cur, nextOff, jumped, labels), strings.ToLower(strings.Join(labels, ".")), nil
		}
		if length&0xc0 == 0xc0 {
			cur, nextOff, jumped, err = stepDNSCompression(raw, cur, nextOff, jumped, &jumps)
			if err != nil {
				return 0, "", err
			}
			continue
		}
		label, nextCur, lErr := readDNSLabel(raw, cur, length)
		if lErr != nil {
			return 0, "", lErr
		}
		octets += 1 + length
		if octets > 255 {
			return 0, "", fmt.Errorf("%w: DNS 解码域名超过 RFC 1035 255 字节上限", ports.ErrCorruptData)
		}
		labels = append(labels, label)
		cur = nextCur
	}
}

func finishDNSName(cur, nextOff int, jumped bool, _ []string) int {
	if !jumped {
		return cur + 1
	}
	return nextOff
}

func stepDNSCompression(raw []byte, cur, nextOff int, jumped bool, jumps *int) (int, int, bool, error) {
	nextCur, err := followDNSCompression(raw, cur, jumps)
	if err != nil {
		return 0, 0, false, err
	}
	if !jumped {
		return nextCur, cur + 2, true, nil
	}
	return nextCur, nextOff, true, nil
}

func readDNSLabel(raw []byte, cur, length int) (string, int, error) {
	if length&0xc0 != 0 || cur+1+length > len(raw) {
		return "", 0, fmt.Errorf("%w: DNS 标签长度或标志位非法", ports.ErrCorruptData)
	}
	return string(raw[cur+1 : cur+1+length]), cur + 1 + length, nil
}

func followDNSCompression(raw []byte, cur int, jumps *int) (int, error) {
	*jumps++
	if *jumps > maxDNSNameJumps || cur+1 >= len(raw) {
		return 0, fmt.Errorf("%w: DNS 压缩指针环路或截断", ports.ErrCorruptData)
	}
	ptr := int(binary.BigEndian.Uint16(raw[cur:cur+2]) & 0x3fff)
	if ptr >= len(raw) {
		return 0, fmt.Errorf("%w: DNS 压缩指针越界", ports.ErrCorruptData)
	}
	return ptr, nil
}

func extractSSHFPRecords(msg parsedDNSMessage, qname string, authenticated bool) ([]ports.SSHFPRecord, error) {
	target := strings.ToLower(strings.TrimSuffix(qname, "."))
	seen := make(map[string]bool, maxCNAMEHops)
	for range maxCNAMEHops {
		next, found := findCNAMETarget(msg.answers, target)
		if !found {
			break
		}
		if seen[next] {
			return nil, fmt.Errorf("%w: DNS CNAME 链存在环路", ports.ErrCorruptData)
		}
		seen[next] = true
		target = next
	}
	if _, stillCNAME := findCNAMETarget(msg.answers, target); stillCNAME {
		return nil, fmt.Errorf("%w: DNS CNAME 链超过最大跳数上限 %d", ports.ErrCorruptData, maxCNAMEHops)
	}
	var out []ports.SSHFPRecord
	for _, rr := range msg.answers {
		if rr.class != dnsClassIN || rr.rtype != dnsTypeSSHFP || rr.name != target {
			continue
		}
		rec, err := decodeSSHFPRData(rr.rdata, authenticated)
		if err != nil {
			if errors.Is(err, ports.ErrInvalidArgument) {
				// RFC 4255 兼容性：跳过未知算法或未来摘要类型的 SSHFP 记录，其余有效记录仍保留。
				continue
			}
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

func findCNAMETarget(answers []parsedDNSRecord, owner string) (string, bool) {
	for _, rr := range answers {
		if rr.class == dnsClassIN && rr.rtype == dnsTypeCNAME && rr.name == owner {
			return string(rr.rdata), true
		}
	}
	return "", false
}

func decodeSSHFPRData(rdata []byte, authenticated bool) (ports.SSHFPRecord, error) {
	var zero ports.SSHFPRecord
	if len(rdata) < 3 {
		return zero, fmt.Errorf("%w: SSHFP RDATA 长度不足", ports.ErrInvalidArgument)
	}
	return ports.NewSSHFPRecord(ports.SSHFPRecordSpec{
		Algorithm:       rdata[0],
		FingerprintType: rdata[1],
		Digest:          rdata[2:],
		Authenticated:   authenticated,
	})
}
