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
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// parseWALGenerationBytes 逐行校验 CRC32 与记录摘要；遇首处截断或损坏立即停机并返回带有效前缀的损坏快照。
func parseWALGenerationBytes(transferID security.OperationID, gen uint64, raw []byte) (ports.JournalGenerationSnapshot, error) {
	if len(raw) == 0 {
		return ports.NewCorruptJournalGenerationSnapshot(gen, fmt.Errorf("%w: %w: 世代 %d WAL 文件为空", ports.ErrCorruptData, ErrCorruptJournalFrame, gen))
	}
	hasTrailingNL := bytes.HasSuffix(raw, []byte{'\n'})
	body := bytes.TrimSuffix(raw, []byte{'\n'})
	lines := bytes.Split(body, []byte{'\n'})
	prefix := make([]fsm.TransferJournalRecord, 0, len(lines))
	for i, line := range lines {
		if i == len(lines)-1 && !hasTrailingNL {
			cause := fmt.Errorf("%w: %w: 第 %d 行缺少尾随换行符（疑似写入截断）", ports.ErrCorruptData, ErrCorruptJournalFrame, i+1)
			return ports.NewCorruptJournalGenerationSnapshot(gen, cause, sortJournalRecordsStable(prefix)...)
		}
		rec, err := decodeWALFrame(line, transferID, gen)
		if err != nil {
			cause := fmt.Errorf("%w: 第 %d 行: %w", ports.ErrCorruptData, i+1, err)
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
		return nil, fmt.Errorf("%w: 序列化 Journal 记录失败: %w", ports.ErrInvalidArgument, err)
	}
	if bytes.ContainsAny(payload, "\r\n") {
		return nil, fmt.Errorf("%w: 规范 JSON 记录包含非法换行符", ports.ErrInvalidArgument)
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
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: 帧头缺失或版本前缀非法", ErrCorruptJournalFrame)
	}
	rest := line[len(walFrameVersionPrefix):]
	if len(rest) <= walCRC32HexLen+1 || rest[walCRC32HexLen] != ':' {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: CRC32 分隔符缺失", ErrCorruptJournalFrame)
	}
	crcHex := string(rest[:walCRC32HexLen])
	wantCRC, err := strconv.ParseUint(crcHex, 16, 32)
	if err != nil || crcHex != strings.ToLower(crcHex) {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: CRC32 十六进制格式非法", ErrCorruptJournalFrame)
	}
	payload := rest[walCRC32HexLen+1:]
	if uint64(crc32.ChecksumIEEE(payload)) != wantCRC {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: CRC32 校验和不匹配", ErrCorruptJournalFrame)
	}
	var rec fsm.TransferJournalRecord
	if err := jsonv2.Unmarshal(payload, &rec); err != nil {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: 载荷反序列化或摘要校验失败: %w", ErrCorruptJournalFrame, err)
	}
	if !rec.IsValid() || !rec.TransferID().Equal(wantID) || rec.Generation() != wantGen {
		return zeroVal[fsm.TransferJournalRecord](), fmt.Errorf("%w: 记录归属 (transfer_id/generation) 与文件不匹配", ErrCorruptJournalFrame)
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
		return zeroVal[security.OperationID](), 0, fmt.Errorf("%w: 非法世代号 %q", ErrCorruptJournalFrame, genStr)
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
