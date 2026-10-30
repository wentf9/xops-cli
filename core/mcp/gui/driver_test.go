package gui

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func TestBuildScriptAndValidate(t *testing.T) {
	script, err := BuildScript(Request{Action: ActionClick, Coord: []int{500, 250}})
	if err != nil {
		t.Fatalf("BuildScript click failed: %v", err)
	}
	if !strings.Contains(script, "PX1=$(( 500 * RES_W / 1000 ))") {
		t.Fatalf("expected scaled X coordinate in script:\n%s", script)
	}
	if !strings.Contains(script, "xdotool mousemove \"$PX1\" \"$PY1\" click 1") {
		t.Fatalf("expected xdotool click fallback in script:\n%s", script)
	}
	if !strings.Contains(script, "sleep 0.5") {
		t.Fatalf("expected post-mutation delay in script:\n%s", script)
	}

	shotScript, err := BuildScript(Request{Action: ActionShot})
	if err != nil {
		t.Fatalf("BuildScript shot failed: %v", err)
	}
	if strings.Contains(shotScript, "sleep 0.5") {
		t.Fatalf("shot action must not sleep before capturing:\n%s", shotScript)
	}

	if _, err := BuildScript(Request{Action: ActionClick, Coord: []int{1200, 100}}); err == nil {
		t.Fatal("expected error for out-of-range coordinate")
	}
	if _, err := BuildScript(Request{Action: ActionDrag, Coord: []int{10, 20}}); err == nil {
		t.Fatal("expected error for drag with 2 coords")
	}
	if _, err := BuildScript(Request{Action: ActionType}); err == nil {
		t.Fatal("expected error for empty type text")
	}
}

func TestBuildScriptScrollDirections(t *testing.T) {
	scrollWithCoord, err := BuildScript(Request{Action: ActionScroll, Coord: []int{400, 600}, Text: "up"})
	if err != nil {
		t.Fatalf("BuildScript scroll with coord failed: %v", err)
	}
	if !strings.Contains(scrollWithCoord, "ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\" && ydotool mousemove --wheel -- -x 0 -y 3") {
		t.Fatalf("expected Wayland ydotool scroll with coord in script:\n%s", scrollWithCoord)
	}
	if !strings.Contains(scrollWithCoord, "xdotool mousemove \"$PX1\" \"$PY1\" click --repeat 3 4") {
		t.Fatalf("expected X11 xdotool scroll fallback with coord in script:\n%s", scrollWithCoord)
	}

	scrollNoCoord, err := BuildScript(Request{Action: ActionScroll, Text: "down"})
	if err != nil {
		t.Fatalf("BuildScript scroll without coord failed: %v", err)
	}
	if !strings.Contains(scrollNoCoord, "ydotool mousemove --wheel -- -x 0 -y -3") || strings.Contains(scrollNoCoord, "ydotool mousemove --absolute") {
		t.Fatalf("expected Wayland ydotool wheel-only scroll in script:\n%s", scrollNoCoord)
	}
	if !strings.Contains(scrollNoCoord, "xdotool click --repeat 3 5") {
		t.Fatalf("expected X11 xdotool wheel-only scroll fallback in script:\n%s", scrollNoCoord)
	}

	scrollLeft, err := BuildScript(Request{Action: ActionScroll, Text: "left"})
	if err != nil {
		t.Fatalf("BuildScript scroll left failed: %v", err)
	}
	if !strings.Contains(scrollLeft, "ydotool mousemove --wheel -- -x -3 -y 0") || !strings.Contains(scrollLeft, "xdotool click --repeat 3 6") {
		t.Fatalf("expected Wayland/X11 left scroll in script:\n%s", scrollLeft)
	}

	scrollRight, err := BuildScript(Request{Action: ActionScroll, Coord: []int{250, 750}, Text: "right"})
	if err != nil {
		t.Fatalf("BuildScript scroll right failed: %v", err)
	}
	if !strings.Contains(scrollRight, "ydotool mousemove --absolute -x \"$PX1\" -y \"$PY1\" && ydotool mousemove --wheel -- -x 3 -y 0") || !strings.Contains(scrollRight, "xdotool mousemove \"$PX1\" \"$PY1\" click --repeat 3 7") {
		t.Fatalf("expected Wayland/X11 right scroll with coord in script:\n%s", scrollRight)
	}
}

func TestBuildScriptUsesPrivateTempDirAndXAuthority(t *testing.T) {
	script, err := BuildScript(Request{Action: ActionShot})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "$$") || !strings.Contains(script, "mktemp -d") {
		t.Fatalf("screenshot must use a private mktemp directory, not a predictable path:\n%s", script)
	}
	if !strings.Contains(script, "XAUTHORITY") {
		t.Fatalf("script must provide an X authority fallback:\n%s", script)
	}
}

func TestExtractAndProcessImageDownscalesTo1280(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 2560, 1440))
	for y := 0; y < 1440; y += 16 {
		for x := 0; x < 2560; x += 16 {
			src.SetRGBA(x, y, color.RGBA{R: 40, G: 120, B: 200, A: 255})
		}
	}
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, src); err != nil {
		t.Fatalf("encode test png: %v", err)
	}

	framed := "some stdout\n" + imageBeginMarker + "\n" +
		base64.StdEncoding.EncodeToString(pngBuf.Bytes()) + "\n" +
		imageEndMarker + "\n"

	compressed, mimeType, err := ExtractAndProcessImage(framed)
	if err != nil {
		t.Fatalf("ExtractAndProcessImage failed: %v", err)
	}
	if mimeType != "image/jpeg" {
		t.Fatalf("expected image/jpeg, got %s", mimeType)
	}

	decoded, _, err := image.Decode(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("decode compressed image: %v", err)
	}
	if decoded.Bounds().Dx() != 1280 || decoded.Bounds().Dy() != 720 {
		t.Fatalf("expected downscaled 1280x720, got %dx%d", decoded.Bounds().Dx(), decoded.Bounds().Dy())
	}
}

func TestProcessImageWebPPassthrough(t *testing.T) {
	fakeWebP := []byte("RIFF\x00\x00\x00\x00WEBPVP8 ")
	out, mimeType, err := ProcessImage(fakeWebP)
	if err != nil {
		t.Fatalf("ProcessImage webp failed: %v", err)
	}
	if mimeType != "image/webp" || !bytes.Equal(out, fakeWebP) {
		t.Fatalf("expected webp passthrough, got %s %v", mimeType, out)
	}
}
