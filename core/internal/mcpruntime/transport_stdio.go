package mcpruntime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
)

const stdioReadBufBytes = 64 * 1024

// ServeStdio 启动标准 MCP stdio（换行分隔 JSON-RPC 2.0）单流同步传输循环：
//   - 启动前自动执行 Prepare（O(1) 崩溃审计对账 + RecoverJournals）；
//   - 严格实施入站单条报文大小有界读取（防 OOM 炸弹），逐条同步保序处理并输出响应行（0 裸 go）；
//   - 输入流到达 io.EOF 时确定性退出并返回 nil；若上层（如 entry/mcpcmd）在阻塞读期间取消 ctx 或调用 Server.Close，
//     调用方需同时关闭传入的 in 读端以立即解除底层阻塞读取并完成优雅停机。
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	if in == nil || out == nil {
		return domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldNil, domi18n.Str("field", "stdio_io"))
	}
	runCtx, cleanup, err := s.beginTransport(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	if _, err := s.Prepare(runCtx); err != nil {
		return err
	}
	return s.serveStdioLoop(runCtx, in, out)
}

func (s *Server) serveStdioLoop(ctx context.Context, in io.Reader, out io.Writer) error {
	br := bufio.NewReaderSize(in, stdioReadBufBytes)
	var writeMu sync.Mutex
	writeLine := func(raw []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		frame := make([]byte, len(raw)+1)
		copy(frame, raw)
		frame[len(raw)] = '\n'
		_, wErr := out.Write(frame)
		return wErr
	}
	for {
		done, err := s.stepStdioMessage(ctx, br, writeLine)
		if done || err != nil {
			return err
		}
	}
}

func (s *Server) stepStdioMessage(ctx context.Context, br *bufio.Reader, writeLine func([]byte) error) (bool, error) {
	if ctx.Err() != nil {
		if errors.Is(context.Cause(ctx), ErrServerClosed) {
			return true, nil
		}
		return true, ctx.Err()
	}
	line, tooLarge, readErr := readBoundedNDJSONLine(br, s.maxMessageBytes)
	if tooLarge {
		if err := writeStdioOversizeError(writeLine); err != nil {
			return true, err
		}
		return errors.Is(readErr, io.EOF), nil
	}
	if len(line) > 0 {
		if err := s.processStdioLine(ctx, line, writeLine); err != nil {
			return true, err
		}
	}
	return handleStdioReadErr(ctx, readErr)
}

func writeStdioOversizeError(writeLine func([]byte) error) error {
	resp, has, encErr := encodeErrResp(algebraic.None[protocol.RequestID](), protocol.CodeInvalidRequest, ErrMessageTooLarge.Error(), protocol.ToolErrorPayload{
		Code: "message_too_large", Message: ErrMessageTooLarge.Error(),
	})
	if encErr != nil || !has {
		return encErr
	}
	return writeLine(resp)
}

func (s *Server) processStdioLine(ctx context.Context, line []byte, writeLine func([]byte) error) error {
	resp, has, err := s.HandleMessage(ctx, line)
	if err != nil || !has {
		return err
	}
	return writeLine(resp)
}

func handleStdioReadErr(ctx context.Context, readErr error) (bool, error) {
	if readErr == nil {
		return false, nil
	}
	if errors.Is(readErr, io.EOF) {
		return true, nil
	}
	if ctx.Err() != nil && errors.Is(context.Cause(ctx), ErrServerClosed) {
		return true, nil
	}
	return true, readErr
}

// readBoundedNDJSONLine 从 br 读取单行换行分隔 JSON 报文并严格强制 maxBytes 内存上限；
// 超限时丢弃该行剩余字节直至换行符或 EOF 并返回 tooLarge=true，确保永不因畸形巨行导致 OOM。
func readBoundedNDJSONLine(br *bufio.Reader, maxBytes int64) (line []byte, tooLarge bool, err error) {
	var acc []byte
	for {
		frag, rErr := br.ReadSlice('\n')
		acc, tooLarge = appendBoundedFrag(acc, frag, maxBytes, tooLarge)
		if errors.Is(rErr, bufio.ErrBufferFull) {
			continue
		}
		if tooLarge {
			return nil, true, rErr
		}
		return bytes.TrimSpace(acc), false, rErr
	}
}

func appendBoundedFrag(acc, frag []byte, maxBytes int64, alreadyTooLarge bool) ([]byte, bool) {
	if alreadyTooLarge {
		return nil, true
	}
	if len(frag) == 0 {
		return acc, false
	}
	if int64(len(acc)+len(frag)) > maxBytes {
		return nil, true
	}
	return append(acc, frag...), false
}
