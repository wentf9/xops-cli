package store

import (
	"bytes"
	"cmp"
	"encoding/base32"
	jsonv2 "encoding/json/v2"
	"fmt"
	"hash/crc32"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// parseWALGenerationBytes 逐行校验 CRC32 与记录摘要；遇首处截断或损坏立即停机并返回带有效前缀的损坏快照。
func parseWALGenerationBytes(transferID security.OperationID, gen uint64, raw []byte) (ports.JournalGenerationSnapshot, error) {
	if len(raw) == 0 {
		return ports.NewCorruptJournalGenerationSnapshot(gen, domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALEmpty, i18n.Uint64("generation", gen))))
	}
	hasTrailingNL := bytes.HasSuffix(raw, []byte{'\n'})
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	lines := bytes.Split(body, []byte{'\n'})
	prefix := make([]fsm.TransferJournalRecord, 0, len(lines))
	for i, line := range lines {
		if i == len(lines)-1 && !hasTrailingNL {
			cause := domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALTruncatedLine, i18n.Int("line", i+1)))
			return ports.NewCorruptJournalGenerationSnapshot(gen, cause, sortJournalRecordsStable(prefix)...)
		}
		rec, err := decodeWALFrame(line, transferID, gen)
		if err != nil {
			cause := i18n.WrapS(ports.ErrCorruptData, err, i18n.KeyHostStoreWALLineError, i18n.Int("line", i+1))
			return ports.NewCorruptJournalGenerationSnapshot(gen, cause, sortJournalRecordsStable(prefix)...)
		}
		prefix = append(prefix, rec)
	}
	return ports.NewJournalGenerationSnapshot(gen, sortJournalRecordsStable(prefix))
}

func sortJournalRecordsStable(in []fsm.TransferJournalRecord) []fsm.TransferJournalRecord {
	if len(in) <= 1 {
		return in
	}
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(a, b fsm.TransferJournalRecord) int { return cmp.Compare(a.Seq(), b.Seq()) })
	return out
}

func encodeWALFrame(rec fsm.TransferJournalRecord) ([]byte, error) {
	payload, err := jsonv2.Marshal(rec, jsonv2.Deterministic(true))
	if err != nil {
		return nil, i18n.WrapS(ports.ErrInvalidArgument, err, i18n.KeyHostStoreWALMarshalFailed)
	}
	if bytes.ContainsAny(payload, "\r\n") {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostStoreWALMarshalFailed)
	}
	sum := crc32.ChecksumIEEE(payload)
	buf := make([]byte, 0, len(walFrameVersionPrefix)+walCRC32HexLen+1+len(payload))
	buf = append(buf, walFrameVersionPrefix...)
	buf = fmt.Appendf(buf, "%08x:", sum)
	buf = append(buf, payload...)
	return buf, nil
}

func decodeWALFrame(rawLine []byte, wantID security.OperationID, wantGen uint64) (fsm.TransferJournalRecord, error) {
	line := bytes.TrimSuffix(rawLine, []byte{'\r'})
	if len(line) < walMinFrameLen || !bytes.HasPrefix(line, []byte(walFrameVersionPrefix)) {
		return zeroVal[fsm.TransferJournalRecord](), i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALInvalidFrame)
	}
	rest := line[len(walFrameVersionPrefix):]
	if len(rest) <= walCRC32HexLen+1 || rest[walCRC32HexLen] != ':' {
		return zeroVal[fsm.TransferJournalRecord](), i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALInvalidFrame)
	}
	crcHex := string(rest[:walCRC32HexLen])
	wantCRC, err := strconv.ParseUint(crcHex, 16, 32)
	if err != nil || crcHex != strings.ToLower(crcHex) {
		return zeroVal[fsm.TransferJournalRecord](), i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALInvalidFrame)
	}
	payload := rest[walCRC32HexLen+1:]
	if uint64(crc32.ChecksumIEEE(payload)) != wantCRC {
		return zeroVal[fsm.TransferJournalRecord](), i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALCRCMismatch)
	}
	var rec fsm.TransferJournalRecord
	if err := jsonv2.Unmarshal(payload, &rec); err != nil {
		return zeroVal[fsm.TransferJournalRecord](), i18n.WrapS(ErrCorruptJournalFrame, err, i18n.KeyHostStoreWALPayloadFailed)
	}
	if !rec.IsValid() || !rec.TransferID().Equal(wantID) || rec.Generation() != wantGen {
		return zeroVal[fsm.TransferJournalRecord](), i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALPayloadFailed)
	}
	return rec, nil
}

// encodeJournalKey 使用无填充小写 Base32（字母表 [a-z2-7]）双射编码 OperationID，
// 确保在 Linux/macOS(APFS)/Windows(NTFS) 大小写不敏感文件系统下零碰撞且满足 255 字节分量上限。
func encodeJournalKey(id security.OperationID) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(id.String()))
	return walKeyPrefix + strings.ToLower(enc)
}

func parseWALFileName(name string) (security.OperationID, uint64, error) {
	if strings.HasSuffix(name, walLockExt) {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	stem, ok := strings.CutSuffix(name, walFileSuffix)
	if !ok {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	keyPart, genStr, ok := strings.Cut(stem, walGenMarker)
	if !ok || !strings.HasPrefix(keyPart, walKeyPrefix) || genStr == "" {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	gen, err := strconv.ParseUint(genStr, 10, 64)
	if err != nil || gen == 0 || strconv.FormatUint(gen, 10) != genStr {
		return zeroVal[security.OperationID](), 0, i18n.EF(ErrCorruptJournalFrame, i18n.KeyHostStoreWALInvalidFrame)
	}
	rawBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimPrefix(keyPart, walKeyPrefix)))
	if err != nil {
		return zeroVal[security.OperationID](), 0, err
	}
	id, err := security.ParseOperationID(string(rawBytes))
	if err != nil {
		return zeroVal[security.OperationID](), 0, err
	}
	if encodeJournalKey(id) != keyPart {
		return zeroVal[security.OperationID](), 0, ErrCorruptJournalFrame
	}
	return id, gen, nil
}
