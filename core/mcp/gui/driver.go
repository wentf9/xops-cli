// Package gui provides Wayland/X11 adaptive desktop automation script
// generation and pure-Go screenshot downscaling for the MCP gui tool.
package gui

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png" // Register PNG decoder
	"regexp"
	"strings"
)

const (
	ActionShot        = "shot"
	ActionClick       = "click"
	ActionDoubleClick = "double_click"
	ActionRightClick  = "right_click"
	ActionMove        = "move"
	ActionType        = "type"
	ActionKey         = "key"
	ActionScroll      = "scroll"
	ActionDrag        = "drag"

	MaxImageDimension = 1280
	JPEGQuality       = 75
	// CaptureOutputLimit bounds the base64 screenshot captured from the
	// remote script. It covers an uncompressed-ish 4K PNG (~25 MiB encoded).
	CaptureOutputLimit = 48 << 20

	imageBeginMarker = "___MCP_GUI_IMG_BEGIN___"
	imageEndMarker   = "___MCP_GUI_IMG_END___"
)

var displayPattern = regexp.MustCompile(`^:[0-9]+(\.[0-9]+)?$`)

// Request describes a normalized GUI action.
type Request struct {
	Action  string
	Coord   []int
	Text    string
	Display string
}

// Validate checks action, coordinate bounds (0-1000), and required parameters.
func (r Request) Validate() error {
	if r.Display != "" && !displayPattern.MatchString(r.Display) {
		return fmt.Errorf("invalid display %q: must match ^:[0-9]+(\\.[0-9]+)?$", r.Display)
	}
	for _, c := range r.Coord {
		if c < 0 || c > 1000 {
			return fmt.Errorf("coordinate %d out of normalized [0, 1000] range", c)
		}
	}
	switch r.Action {
	case ActionShot:
		return nil
	case ActionClick, ActionDoubleClick, ActionRightClick, ActionMove:
		if len(r.Coord) != 2 {
			return fmt.Errorf("action %q requires [x, y] coordinates", r.Action)
		}
		return nil
	case ActionDrag:
		if len(r.Coord) != 4 {
			return fmt.Errorf("action %q requires [start_x, start_y, end_x, end_y] coordinates", r.Action)
		}
		return nil
	case ActionType, ActionKey:
		if r.Text == "" {
			return fmt.Errorf("action %q requires non-empty text", r.Action)
		}
		return nil
	case ActionScroll:
		if len(r.Coord) != 0 && len(r.Coord) != 2 {
			return fmt.Errorf("action %q accepts optional [x, y] coordinates", r.Action)
		}
		dir := strings.ToLower(strings.TrimSpace(r.Text))
		if dir != "up" && dir != "down" && dir != "left" && dir != "right" {
			return fmt.Errorf("action %q requires text direction up, down, left, or right", r.Action)
		}
		return nil
	default:
		return fmt.Errorf("unsupported gui action %q", r.Action)
	}
}

// IsReadOnly reports whether the GUI action does not mutate application state.
func IsReadOnly(action string) bool {
	return action == ActionShot || action == ActionMove
}

// BuildScript constructs a self-contained POSIX shell script that adapts to
// Wayland or X11, executes the action, waits 500ms on mutations, and outputs a
// base64-encoded screenshot between markers.
func BuildScript(req Request) (string, error) {
	if err := req.Validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("if [ -z \"${XDG_RUNTIME_DIR:-}\" ]; then\n")
	b.WriteString("  _uid=$(id -u 2>/dev/null || true)\n")
	b.WriteString("  if [ -n \"$_uid\" ] && [ -d \"/run/user/$_uid\" ]; then\n")
	b.WriteString("    export XDG_RUNTIME_DIR=\"/run/user/$_uid\"\n")
	b.WriteString("  fi\n")
	b.WriteString("fi\n")
	if req.Display != "" {
		fmt.Fprintf(&b, "export DISPLAY=%s\n", shellQuote(req.Display))
	} else {
		b.WriteString("if [ -z \"${WAYLAND_DISPLAY:-}\" ] && [ -n \"${XDG_RUNTIME_DIR:-}\" ] && [ -S \"$XDG_RUNTIME_DIR/wayland-0\" ]; then\n")
		b.WriteString("  export WAYLAND_DISPLAY=\"wayland-0\"\n")
		b.WriteString("fi\n")
		b.WriteString("if [ -z \"${DISPLAY:-}\" ]; then\n")
		b.WriteString("  if [ ! -S /tmp/.X11-unix/X0 ]; then\n")
		b.WriteString("    for _sock in /tmp/.X11-unix/X*; do\n")
		b.WriteString("      if [ -S \"$_sock\" ]; then DISPLAY=\":${_sock#/tmp/.X11-unix/X}\"; break; fi\n")
		b.WriteString("    done\n")
		b.WriteString("  fi\n")
		b.WriteString("  export DISPLAY=\"${DISPLAY:-:0}\"\n")
		b.WriteString("fi\n")
	}
	b.WriteString("if [ -z \"${XAUTHORITY:-}\" ]; then\n")
	b.WriteString("  if [ -r \"$HOME/.Xauthority\" ]; then\n")
	b.WriteString("    export XAUTHORITY=\"$HOME/.Xauthority\"\n")
	b.WriteString("  elif [ -n \"${XDG_RUNTIME_DIR:-}\" ]; then\n")
	b.WriteString("    for _auth in \"$XDG_RUNTIME_DIR\"/.mutter-Xwaylandauth.*; do\n")
	b.WriteString("      if [ -r \"$_auth\" ]; then export XAUTHORITY=\"$_auth\"; break; fi\n")
	b.WriteString("    done\n")
	b.WriteString("    if [ -z \"${XAUTHORITY:-}\" ] && [ -r \"$XDG_RUNTIME_DIR/gdm/Xauthority\" ]; then\n")
	b.WriteString("      export XAUTHORITY=\"$XDG_RUNTIME_DIR/gdm/Xauthority\"\n")
	b.WriteString("    elif [ -z \"${XAUTHORITY:-}\" ] && [ -r \"$XDG_RUNTIME_DIR/Xauthority\" ]; then\n")
	b.WriteString("      export XAUTHORITY=\"$XDG_RUNTIME_DIR/Xauthority\"\n")
	b.WriteString("    fi\n")
	b.WriteString("  fi\n")
	b.WriteString("fi\n")
	b.WriteString("RES=$(xdpyinfo 2>/dev/null | awk '/dimensions:/ {print $2; exit}' || true)\n")
	b.WriteString("if [ -z \"$RES\" ]; then RES=$(xrandr 2>/dev/null | awk '/\\*/ {print $1; exit}' || true); fi\n")
	b.WriteString("RES_W=$(printf '%s' \"$RES\" | cut -d'x' -f1)\n")
	b.WriteString("RES_H=$(printf '%s' \"$RES\" | cut -d'x' -f2)\n")
	b.WriteString("case \"$RES_W\" in ''|*[!0-9]*) RES_W=1920 ;; esac\n")
	b.WriteString("case \"$RES_H\" in ''|*[!0-9]*) RES_H=1080 ;; esac\n")

	if len(req.Coord) >= 2 {
		fmt.Fprintf(&b, "PX1=$(( %d * RES_W / 1000 ))\n", req.Coord[0])
		fmt.Fprintf(&b, "PY1=$(( %d * RES_H / 1000 ))\n", req.Coord[1])
	}
	if len(req.Coord) == 4 {
		fmt.Fprintf(&b, "PX2=$(( %d * RES_W / 1000 ))\n", req.Coord[2])
		fmt.Fprintf(&b, "PY2=$(( %d * RES_H / 1000 ))\n", req.Coord[3])
	}

	if req.Action != ActionShot {
		b.WriteString(buildActionSnippet(req))
		b.WriteString("sleep 0.5 2>/dev/null || sleep 1\n")
	}

	// mktemp -d creates a private 0700 directory, so a pre-planted symlink in
	// a shared temporary directory cannot redirect the screenshot; the .png
	// suffix lets extension-sniffing tools (scrot, import) pick PNG.
	b.WriteString("TMP_DIR=$(mktemp -d \"${TMPDIR:-/tmp}/mcp_gui.XXXXXXXXXX\")\n")
	b.WriteString("trap 'rm -rf \"$TMP_DIR\"' EXIT\n")
	b.WriteString("TMP_IMG=\"$TMP_DIR/shot.png\"\n")
	b.WriteString("if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v grim >/dev/null 2>&1 && grim \"$TMP_IMG\" 2>/dev/null; then\n")
	b.WriteString("  :\n")
	b.WriteString("elif [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v spectacle >/dev/null 2>&1 && spectacle -b -n -o \"$TMP_IMG\" 2>/dev/null; then\n")
	b.WriteString("  :\n")
	b.WriteString("elif command -v maim >/dev/null 2>&1 && maim \"$TMP_IMG\" 2>/dev/null; then\n")
	b.WriteString("  :\n")
	b.WriteString("elif command -v import >/dev/null 2>&1 && import -window root \"$TMP_IMG\" 2>/dev/null; then\n")
	b.WriteString("  :\n")
	b.WriteString("elif command -v scrot >/dev/null 2>&1 && scrot -o \"$TMP_IMG\" 2>/dev/null; then\n")
	b.WriteString("  :\n")
	b.WriteString("elif command -v gnome-screenshot >/dev/null 2>&1 && gnome-screenshot -f \"$TMP_IMG\" 2>/dev/null; then\n")
	b.WriteString("  :\n")
	b.WriteString("else\n")
	b.WriteString("  echo 'no supported screenshot utility found (grim, spectacle, maim, import, scrot, gnome-screenshot)' >&2\n")
	b.WriteString("  exit 127\n")
	b.WriteString("fi\n")
	fmt.Fprintf(&b, "printf '%s\\n'\n", imageBeginMarker)
	b.WriteString("base64 < \"$TMP_IMG\" | tr -d '\\r\\n'\n")
	fmt.Fprintf(&b, "\nprintf '%s\\n'\n", imageEndMarker)

	return b.String(), nil
}

func buildActionSnippet(req Request) string {
	switch req.Action {
	case ActionMove:
		return "if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n" +
			"  ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\"\n" +
			"else\n" +
			"  xdotool mousemove \"$PX1\" \"$PY1\"\n" +
			"fi\n"
	case ActionClick:
		return "if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n" +
			"  ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\" && ydotool click 0xC0\n" +
			"else\n" +
			"  xdotool mousemove \"$PX1\" \"$PY1\" click 1\n" +
			"fi\n"
	case ActionDoubleClick:
		return "if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n" +
			"  ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\" && ydotool click --repeat 2 0xC0\n" +
			"else\n" +
			"  xdotool mousemove \"$PX1\" \"$PY1\" click --repeat 2 1\n" +
			"fi\n"
	case ActionRightClick:
		return "if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n" +
			"  ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\" && ydotool click 0xC1\n" +
			"else\n" +
			"  xdotool mousemove \"$PX1\" \"$PY1\" click 3\n" +
			"fi\n"
	case ActionDrag:
		return "if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n" +
			"  ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\" && ydotool click 0x40 && ydotool mousemove --absolute -x \"$PX2\" -y \"$PY2\" && ydotool click 0x80\n" +
			"else\n" +
			"  xdotool mousemove \"$PX1\" \"$PY1\" mousedown 1 mousemove \"$PX2\" \"$PY2\" mouseup 1\n" +
			"fi\n"
	case ActionType:
		quoted := shellQuote(req.Text)
		return fmt.Sprintf("if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n"+
			"  ydotool type -- %s\n"+
			"else\n"+
			"  xdotool type --clearmodifiers -- %s\n"+
			"fi\n", quoted, quoted)
	case ActionKey:
		quoted := shellQuote(req.Text)
		return fmt.Sprintf("if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n"+
			"  ydotool key %s\n"+
			"else\n"+
			"  xdotool key --clearmodifiers %s\n"+
			"fi\n", quoted, quoted)
	case ActionScroll:
		btn := "5"
		wheelArgs := "-x 0 -y -3"
		switch strings.ToLower(strings.TrimSpace(req.Text)) {
		case "up":
			btn = "4"
			wheelArgs = "-x 0 -y 3"
		case "down":
			btn = "5"
			wheelArgs = "-x 0 -y -3"
		case "left":
			btn = "6"
			wheelArgs = "-x -3 -y 0"
		case "right":
			btn = "7"
			wheelArgs = "-x 3 -y 0"
		}
		waylandMove := ""
		movePrefix := ""
		if len(req.Coord) == 2 {
			waylandMove = "ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\" && "
			movePrefix = "mousemove \"$PX1\" \"$PY1\" "
		}
		return fmt.Sprintf("if [ -n \"${WAYLAND_DISPLAY:-}\" ] && command -v ydotool >/dev/null 2>&1; then\n"+
			"  %sydotool mousemove --wheel -- %s\n"+
			"else\n"+
			"  xdotool %sclick --repeat 3 %s\n"+
			"fi\n", waylandMove, wheelArgs, movePrefix, btn)
	default:
		return ""
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ExtractAndProcessImage extracts the base64 screenshot payload from script
// output and downscales/compresses it via ProcessImage.
func ExtractAndProcessImage(output string) ([]byte, string, error) {
	startIdx := strings.Index(output, imageBeginMarker)
	endIdx := strings.Index(output, imageEndMarker)
	if startIdx < 0 || endIdx < 0 || endIdx <= startIdx {
		return nil, "", errors.New("gui script output missing screenshot markers")
	}
	b64Payload := strings.TrimSpace(output[startIdx+len(imageBeginMarker) : endIdx])
	b64Payload = strings.Join(strings.Fields(b64Payload), "")
	raw, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return nil, "", fmt.Errorf("decode screenshot base64: %w", err)
	}
	return ProcessImage(raw)
}

// ProcessImage limits the image's longest edge to 1280px and compresses as JPEG
// (quality 75) in pure Go. WebP payloads are passed through directly.
func ProcessImage(raw []byte) ([]byte, string, error) {
	if isWebP(raw) {
		return raw, "image/webp", nil
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("decode image: %w", err)
	}

	bounds := src.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	if w <= 0 || h <= 0 {
		return nil, "", errors.New("decoded image has empty dimensions")
	}

	target := src
	if w > MaxImageDimension || h > MaxImageDimension {
		newW, newH := scaledDimensions(w, h, MaxImageDimension)
		target = resizeBilinear(src, newW, newH)
	}

	var out bytes.Buffer
	if err := jpeg.Encode(&out, target, &jpeg.Options{Quality: JPEGQuality}); err != nil {
		return nil, "", fmt.Errorf("encode compressed jpeg: %w", err)
	}
	return out.Bytes(), "image/jpeg", nil
}

func isWebP(raw []byte) bool {
	return len(raw) >= 12 && string(raw[:4]) == "RIFF" && string(raw[8:12]) == "WEBP"
}

func scaledDimensions(w, h, maxEdge int) (int, int) {
	if w >= h {
		newH := (h * maxEdge) / w
		if newH < 1 {
			newH = 1
		}
		return maxEdge, newH
	}
	newW := (w * maxEdge) / h
	if newW < 1 {
		newW = 1
	}
	return newW, maxEdge
}

func resizeBilinear(src image.Image, dstW, dstH int) *image.RGBA {
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))

	for y := 0; y < dstH; y++ {
		srcYf := (float64(y)+0.5)*float64(srcH)/float64(dstH) - 0.5
		if srcYf < 0 {
			srcYf = 0
		}
		y0 := int(srcYf)
		y1 := y0 + 1
		if y1 >= srcH {
			y1 = srcH - 1
		}
		wy := srcYf - float64(y0)

		for x := 0; x < dstW; x++ {
			srcXf := (float64(x)+0.5)*float64(srcW)/float64(dstW) - 0.5
			if srcXf < 0 {
				srcXf = 0
			}
			x0 := int(srcXf)
			x1 := x0 + 1
			if x1 >= srcW {
				x1 = srcW - 1
			}
			wx := srcXf - float64(x0)

			r00, g00, b00, a00 := src.At(bounds.Min.X+x0, bounds.Min.Y+y0).RGBA()
			r10, g10, b10, a10 := src.At(bounds.Min.X+x1, bounds.Min.Y+y0).RGBA()
			r01, g01, b01, a01 := src.At(bounds.Min.X+x0, bounds.Min.Y+y1).RGBA()
			r11, g11, b11, a11 := src.At(bounds.Min.X+x1, bounds.Min.Y+y1).RGBA()

			w00 := (1 - wx) * (1 - wy)
			w10 := wx * (1 - wy)
			w01 := (1 - wx) * wy
			w11 := wx * wy

			r := uint8((float64(r00)*w00 + float64(r10)*w10 + float64(r01)*w01 + float64(r11)*w11) / 257.0)
			g := uint8((float64(g00)*w00 + float64(g10)*w10 + float64(g01)*w01 + float64(g11)*w11) / 257.0)
			b := uint8((float64(b00)*w00 + float64(b10)*w10 + float64(b01)*w01 + float64(b11)*w11) / 257.0)
			a := uint8((float64(a00)*w00 + float64(a10)*w10 + float64(a01)*w01 + float64(a11)*w11) / 257.0)

			dst.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: a})
		}
	}
	return dst
}
