//go:build windows

package terminal

import (
	"unicode/utf16"
	"unicode/utf8"

	"github.com/erikgeiser/coninput"
)

// appendVTKey follows Windows OpenSSH's modern console input path: VT mode
// already encodes navigation, modifiers and repeats as text. Treat those UTF-16
// characters as a stream instead of applying the legacy key mapping again.
// See PowerShell/openssh-portable, tncon.c: ReadConsoleForTermEmulModern.
func (r *windowsConsolePromptReader) appendVTKey(key coninput.KeyEventRecord) {
	// Windows can deliver Unicode input on a VK_MENU key-up (including emoji
	// injected through ConPTY). Other key-up records contain no new input.
	if !key.KeyDown && key.VirtualKeyCode != coninput.VK_MENU {
		return
	}
	// ConPTY can emit empty modifier records even in VT mode. A zero character
	// with no scan code, however, is a real NUL and must reach the remote app.
	if key.Char == 0 && key.VirtualScanCode != 0 {
		return
	}
	r.appendVTChar(key.Char)
}

func (r *windowsConsolePromptReader) appendVTChar(char rune) {
	if r.highSurrogate != 0 {
		high := r.highSurrogate
		r.highSurrogate = 0
		if char >= 0xdc00 && char <= 0xdfff {
			r.pending = utf8.AppendRune(r.pending, utf16.DecodeRune(high, char))
			return
		}
		// Preserve following input if the source supplied an unpaired surrogate.
		r.pending = utf8.AppendRune(r.pending, utf8.RuneError)
	}
	if char >= 0xd800 && char <= 0xdbff {
		r.highSurrogate = char
		return
	}
	// AppendRune replaces an unpaired low surrogate with RuneError.
	r.pending = utf8.AppendRune(r.pending, char)
}
