package gui

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if !strings.Contains(script, "no supported input utility found (ydotool, xdotool)") {
		t.Fatalf("expected input utility missing error diagnostic in script:\n%s", script)
	}
	if !strings.Contains(script, "exit 127") {
		t.Fatalf("expected exit 127 on missing input utility in script:\n%s", script)
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
	if !strings.Contains(script, "wayland-0") {
		t.Fatalf("script must probe for wayland-0 socket:\n%s", script)
	}
	if !strings.Contains(script, "nonomatch") {
		t.Fatalf("script must set nonomatch for zsh glob compatibility:\n%s", script)
	}
	if !strings.Contains(script, `for _wsock in "$XDG_RUNTIME_DIR"/wayland-*; do`) {
		t.Fatalf("script must probe for wayland-* fallback sockets:\n%s", script)
	}
	if !strings.Contains(script, ".mutter-Xwaylandauth") {
		t.Fatalf("script must probe for mutter Xwayland auth file:\n%s", script)
	}
	if !strings.Contains(script, `"$XDG_RUNTIME_DIR"/xauth_*`) {
		t.Fatalf("script must probe for KDE xauth_* file:\n%s", script)
	}
	if !strings.Contains(script, `-s "$_auth"`) {
		t.Fatalf("script must check that _auth file is non-empty:\n%s", script)
	}
	if !strings.Contains(script, `-s "$HOME/.Xauthority"`) {
		t.Fatalf("script must check that $HOME/.Xauthority is non-empty:\n%s", script)
	}
	if strings.Contains(script, "$(ls") {
		t.Fatalf("script must not use ls command substitution:\n%s", script)
	}
	if !strings.Contains(script, "gdm/Xauthority") {
		t.Fatalf("script must probe for gdm Xauthority:\n%s", script)
	}
	if !strings.Contains(script, "spectacle") {
		t.Fatalf("script must probe for spectacle screenshot utility:\n%s", script)
	}
	if !strings.Contains(script, "gnome-screenshot") {
		t.Fatalf("script must include gnome-screenshot fallback:\n%s", script)
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

func TestBuildScriptExplicitDisplay(t *testing.T) {
	script, err := BuildScript(Request{Action: ActionShot, Display: ":1"})
	if err != nil {
		t.Fatalf("BuildScript with explicit display failed: %v", err)
	}
	if !strings.Contains(script, "export DISPLAY=':1'") {
		t.Fatalf("expected export DISPLAY=':1' in script:\n%s", script)
	}
	if strings.Contains(script, "/tmp/.X11-unix") {
		t.Fatalf("explicit display script must not contain socket scanning:\n%s", script)
	}

	scriptDot, err := BuildScript(Request{Action: ActionShot, Display: ":10.0"})
	if err != nil {
		t.Fatalf("BuildScript with display :10.0 failed: %v", err)
	}
	if !strings.Contains(scriptDot, "export DISPLAY=':10.0'") {
		t.Fatalf("expected export DISPLAY=':10.0' in script:\n%s", scriptDot)
	}
}

func TestBuildScriptAutoDetectDisplay(t *testing.T) {
	script, err := BuildScript(Request{Action: ActionShot})
	if err != nil {
		t.Fatalf("BuildScript with omitted display failed: %v", err)
	}
	if !strings.Contains(script, `for _sock in /tmp/.X11-unix/X*; do`) {
		t.Fatalf("expected /tmp/.X11-unix/X* scan loop in script:\n%s", script)
	}
	if !strings.Contains(script, `export DISPLAY="${DISPLAY:-:0}"`) {
		t.Fatalf("expected fallback DISPLAY export in script:\n%s", script)
	}
}

func TestRequestValidateDisplay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		display string
		wantErr bool
	}{
		{name: "empty display allowed", display: "", wantErr: false},
		{name: "valid display :0", display: ":0", wantErr: false},
		{name: "valid display :1", display: ":1", wantErr: false},
		{name: "valid display :10", display: ":10", wantErr: false},
		{name: "valid display with screen :0.0", display: ":0.0", wantErr: false},
		{name: "valid display with screen :1.2", display: ":1.2", wantErr: false},
		{name: "invalid missing colon 0", display: "0", wantErr: true},
		{name: "invalid letters :a", display: ":a", wantErr: true},
		{name: "invalid space prefix", display: " :0", wantErr: true},
		{name: "invalid space suffix", display: ":0 ", wantErr: true},
		{name: "invalid hostname prefix", display: "localhost:0", wantErr: true},
		{name: "invalid socket path", display: "/tmp/.X11-unix/X1", wantErr: true},
		{name: "invalid command injection semicolon", display: ":0; rm -rf /", wantErr: true},
		{name: "invalid command injection quote", display: ":0'$(whoami)'", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Action: ActionShot, Display: tc.display}
			err := req.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() display %q error = %v, wantErr = %v", tc.display, err, tc.wantErr)
			}
		})
	}
}

func TestBuildScriptActionsIncludeInputDiagnostics(t *testing.T) {
	requests := []Request{
		{Action: ActionMove, Coord: []int{100, 200}},
		{Action: ActionClick, Coord: []int{100, 200}},
		{Action: ActionDoubleClick, Coord: []int{100, 200}},
		{Action: ActionRightClick, Coord: []int{100, 200}},
		{Action: ActionDrag, Coord: []int{100, 200, 300, 400}},
		{Action: ActionType, Text: "hello world"},
		{Action: ActionKey, Text: "Return"},
		{Action: ActionScroll, Coord: []int{100, 200}, Text: "up"},
	}

	for _, req := range requests {
		t.Run(req.Action, func(t *testing.T) {
			script, err := BuildScript(req)
			if err != nil {
				t.Fatalf("BuildScript failed for action %s: %v", req.Action, err)
			}
			if !strings.Contains(script, "command -v ydotool") {
				t.Errorf("action %s missing ydotool check", req.Action)
			}
			if !strings.Contains(script, "elif command -v xdotool >/dev/null 2>&1; then") {
				t.Errorf("action %s missing xdotool check", req.Action)
			}
			if !strings.Contains(script, "no supported input utility found (ydotool, xdotool)") {
				t.Errorf("action %s missing missing-input diagnostic message", req.Action)
			}
			if !strings.Contains(script, "exit 127") {
				t.Errorf("action %s missing exit 127", req.Action)
			}
		})
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	baseDir := ""
	if _, err := os.Stat("/tmp"); err == nil {
		baseDir = "/tmp"
	}
	dir, err := os.MkdirTemp(baseDir, "xgui*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func setupMockWaylandEnv(t *testing.T, tmpDir string) (xdgDir, xauthPath, homeDir string, cleanup func()) {
	t.Helper()
	xdgDir = filepath.Join(tmpDir, "run_user")
	if err := os.MkdirAll(xdgDir, 0700); err != nil {
		t.Fatal(err)
	}

	waylandSockPath := filepath.Join(xdgDir, "wayland-1")
	ln, err := net.Listen("unix", waylandSockPath)
	if err != nil {
		t.Fatalf("create unix socket: %v", err)
	}
	cleanup = func() { _ = ln.Close() }

	if err := os.WriteFile(filepath.Join(xdgDir, "wayland-1.lock"), []byte("lock content"), 0600); err != nil {
		cleanup()
		t.Fatal(err)
	}

	xauthPath = filepath.Join(xdgDir, "xauth_test123")
	if err := os.WriteFile(xauthPath, []byte("valid auth token"), 0600); err != nil {
		cleanup()
		t.Fatal(err)
	}

	homeDir = filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(homeDir, 0700); err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, ".Xauthority"), []byte(""), 0600); err != nil {
		cleanup()
		t.Fatal(err)
	}

	return xdgDir, xauthPath, homeDir, cleanup
}

func createMockSpectacle(t *testing.T, tmpDir, binDir string) {
	t.Helper()
	testImg := image.NewRGBA(image.Rect(0, 0, 100, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			testImg.Set(x, y, color.RGBA{R: 200, G: 100, B: 50, A: 255})
		}
	}
	samplePngPath := filepath.Join(tmpDir, "sample.png")
	f, err := os.Create(samplePngPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, testImg); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	spectacleScript := fmt.Sprintf(`#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    out="$2"
    shift 2
    continue
  fi
  shift
done
if [ -n "$out" ]; then
  cp %s "$out"
  exit 0
fi
exit 1
`, shellQuote(samplePngPath))

	mockSpectacle := filepath.Join(binDir, "spectacle")
	if err := os.WriteFile(mockSpectacle, []byte(spectacleScript), 0755); err != nil {
		t.Fatal(err)
	}
}

func buildIsolatedEnv(binDir, xdgDir, homeDir string) []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env)+3)
	for _, e := range env {
		if strings.HasPrefix(e, "WAYLAND_DISPLAY=") ||
			strings.HasPrefix(e, "DISPLAY=") ||
			strings.HasPrefix(e, "XAUTHORITY=") ||
			strings.HasPrefix(e, "XDG_RUNTIME_DIR=") ||
			strings.HasPrefix(e, "HOME=") ||
			strings.HasPrefix(e, "PATH=") ||
			strings.HasPrefix(e, "ZSH_VERSION=") ||
			strings.HasPrefix(e, "TMPDIR=") {
			continue
		}
		filtered = append(filtered, e)
	}
	return append(filtered,
		"PATH="+binDir+":"+os.Getenv("PATH"),
		"XDG_RUNTIME_DIR="+xdgDir,
		"HOME="+homeDir,
	)
}

func TestBuildScriptShellExecutionWaylandFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell execution test skipped on Windows")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available in test environment")
	}

	tmpDir := shortTempDir(t)
	xdgDir, xauthPath, homeDir, cleanup := setupMockWaylandEnv(t, tmpDir)
	defer cleanup()

	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockSpectacle(t, tmpDir, binDir)

	script, err := BuildScript(Request{Action: ActionShot})
	if err != nil {
		t.Fatalf("BuildScript shot: %v", err)
	}

	mockX11Dir := filepath.Join(tmpDir, "X11-unix")
	if err := os.MkdirAll(mockX11Dir, 0700); err != nil {
		t.Fatal(err)
	}
	script = strings.ReplaceAll(script, "/tmp/.X11-unix", mockX11Dir)

	verificationAppend := "\nprintf 'TEST_WAYLAND_DISPLAY=%s\\n' \"$WAYLAND_DISPLAY\" >&2\nprintf 'TEST_XAUTHORITY=%s\\n' \"$XAUTHORITY\" >&2\n"
	fullScript := script + verificationAppend

	cmd := exec.Command("sh", "-c", fullScript)
	cmd.Env = buildIsolatedEnv(binDir, xdgDir, homeDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("script execution failed: %v\nstderr: %s\nstdout: %s", runErr, stderr.String(), stdout.String())
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "TEST_WAYLAND_DISPLAY=wayland-1") {
		t.Fatalf("expected WAYLAND_DISPLAY to resolve to wayland-1, got stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "TEST_XAUTHORITY="+xauthPath) {
		t.Fatalf("expected XAUTHORITY to resolve to %s, got stderr:\n%s", xauthPath, stderrStr)
	}

	imgBytes, mimeType, err := ExtractAndProcessImage(stdout.String())
	if err != nil {
		t.Fatalf("ExtractAndProcessImage failed on script output: %v", err)
	}
	if mimeType != "image/jpeg" {
		t.Fatalf("expected mimeType image/jpeg, got %s", mimeType)
	}
	if len(imgBytes) == 0 {
		t.Fatal("expected non-empty image bytes")
	}
}

func TestBuildScriptShellExecutionInputMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell execution test skipped on Windows")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available in test environment")
	}

	tmpDir := shortTempDir(t)
	binDir := filepath.Join(tmpDir, "isolated_bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Link essential shell commands into isolated_bin so ydotool/xdotool are guaranteed absent
	requiredTools := []string{"sh", "id", "mktemp", "sleep", "cut", "printf", "awk", "base64", "tr"}
	for _, tool := range requiredTools {
		p, err := exec.LookPath(tool)
		if err == nil {
			_ = os.Symlink(p, filepath.Join(binDir, tool))
		}
	}

	script, err := BuildScript(Request{Action: ActionMove, Coord: []int{500, 500}})
	if err != nil {
		t.Fatalf("BuildScript move: %v", err)
	}

	cmd := exec.Command("sh", "-c", script)
	cmd.Env = []string{
		"PATH=" + binDir,
		"HOME=" + tmpDir,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err == nil {
		t.Fatal("expected script to fail with exit 127 when input utilities are missing")
	}
	if !strings.Contains(err.Error(), "exit status 127") {
		t.Fatalf("expected exit status 127, got: %v", err)
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "no supported input utility found (ydotool, xdotool)") {
		t.Fatalf("expected stderr to contain 'no supported input utility found (ydotool, xdotool)', got:\n%s", stderrStr)
	}
}

func TestBuildScriptShellExecutionDisplayResolutionProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell execution test skipped on Windows")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available in test environment")
	}

	t.Run("wayland_socket_mapping", testWaylandSocketMapping)
	t.Run("display_fallback_loop", testDisplayFallbackLoop)
}

func testWaylandSocketMapping(t *testing.T) {
	tmpDir := shortTempDir(t)
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockSpectacle(t, tmpDir, binDir)

	mockYdotool := filepath.Join(binDir, "ydotool")
	if err := os.WriteFile(mockYdotool, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	mockXdpyinfo := filepath.Join(binDir, "xdpyinfo")
	xdpyinfoScript := `#!/bin/sh
if [ "$DISPLAY" = ":1" ]; then
  echo "  dimensions:    3840x2160 pixels"
  exit 0
fi
echo "unable to open display $DISPLAY" >&2
exit 1
`
	if err := os.WriteFile(mockXdpyinfo, []byte(xdpyinfoScript), 0755); err != nil {
		t.Fatal(err)
	}

	xdgDir := filepath.Join(tmpDir, "run_user")
	if err := os.MkdirAll(xdgDir, 0700); err != nil {
		t.Fatal(err)
	}
	waylandSockPath := filepath.Join(xdgDir, "wayland-1")
	wln, err := net.Listen("unix", waylandSockPath)
	if err != nil {
		t.Fatalf("create wayland socket: %v", err)
	}
	defer func() { _ = wln.Close() }()

	mockX11Dir := filepath.Join(tmpDir, "X11-unix")
	if err := os.MkdirAll(mockX11Dir, 0700); err != nil {
		t.Fatal(err)
	}
	x1SockPath := filepath.Join(mockX11Dir, "X1")
	x1ln, err := net.Listen("unix", x1SockPath)
	if err != nil {
		t.Fatalf("create X1 socket: %v", err)
	}
	defer func() { _ = x1ln.Close() }()

	script, err := BuildScript(Request{Action: ActionMove, Coord: []int{500, 500}})
	if err != nil {
		t.Fatalf("BuildScript move: %v", err)
	}
	script = strings.ReplaceAll(script, "/tmp/.X11-unix", mockX11Dir)

	verificationAppend := "\nprintf 'TEST_DISPLAY=%s\\n' \"$DISPLAY\" >&2\nprintf 'TEST_RES=%s\\n' \"$RES\" >&2\nprintf 'TEST_PX1=%s\\n' \"$PX1\" >&2\nprintf 'TEST_PY1=%s\\n' \"$PY1\" >&2\n"
	fullScript := script + verificationAppend

	cmd := exec.Command("sh", "-c", fullScript)
	cmd.Env = buildIsolatedEnv(binDir, xdgDir, tmpDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("script execution failed: %v\nstderr: %s\nstdout: %s", runErr, stderr.String(), stdout.String())
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "TEST_DISPLAY=:1") {
		t.Fatalf("expected DISPLAY to resolve to :1, got stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "TEST_RES=3840x2160") {
		t.Fatalf("expected resolution 3840x2160, got stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "TEST_PX1=1920") {
		t.Fatalf("expected PX1=1920 (scaled for 3840x2160), got stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "TEST_PY1=1080") {
		t.Fatalf("expected PY1=1080 (scaled for 3840x2160), got stderr:\n%s", stderrStr)
	}
}

func testDisplayFallbackLoop(t *testing.T) {
	tmpDir := shortTempDir(t)
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockSpectacle(t, tmpDir, binDir)

	mockXdotool := filepath.Join(binDir, "xdotool")
	if err := os.WriteFile(mockXdotool, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	mockXdpyinfo := filepath.Join(binDir, "xdpyinfo")
	xdpyinfoScript := `#!/bin/sh
if [ "$DISPLAY" = ":2" ]; then
  echo "  dimensions:    2560x1440 pixels"
  exit 0
fi
echo "unable to open display $DISPLAY" >&2
exit 1
`
	if err := os.WriteFile(mockXdpyinfo, []byte(xdpyinfoScript), 0755); err != nil {
		t.Fatal(err)
	}

	mockX11Dir := filepath.Join(tmpDir, "X11-unix")
	if err := os.MkdirAll(mockX11Dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Create X0 (which fails xdpyinfo) and X2 (which succeeds)
	x0SockPath := filepath.Join(mockX11Dir, "X0")
	x0ln, err := net.Listen("unix", x0SockPath)
	if err != nil {
		t.Fatalf("create X0 socket: %v", err)
	}
	defer func() { _ = x0ln.Close() }()

	x2SockPath := filepath.Join(mockX11Dir, "X2")
	x2ln, err := net.Listen("unix", x2SockPath)
	if err != nil {
		t.Fatalf("create X2 socket: %v", err)
	}
	defer func() { _ = x2ln.Close() }()

	script, err := BuildScript(Request{Action: ActionMove, Coord: []int{500, 500}})
	if err != nil {
		t.Fatalf("BuildScript move: %v", err)
	}
	script = strings.ReplaceAll(script, "/tmp/.X11-unix", mockX11Dir)

	verificationAppend := "\nprintf 'TEST_DISPLAY=%s\\n' \"$DISPLAY\" >&2\nprintf 'TEST_RES=%s\\n' \"$RES\" >&2\nprintf 'TEST_PX1=%s\\n' \"$PX1\" >&2\nprintf 'TEST_PY1=%s\\n' \"$PY1\" >&2\n"
	fullScript := script + verificationAppend

	cmd := exec.Command("sh", "-c", fullScript)
	cmd.Env = buildIsolatedEnv(binDir, tmpDir, tmpDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		t.Fatalf("script execution failed: %v\nstderr: %s\nstdout: %s", runErr, stderr.String(), stdout.String())
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "TEST_DISPLAY=:2") {
		t.Fatalf("expected DISPLAY to fallback to :2, got stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "TEST_RES=2560x1440") {
		t.Fatalf("expected resolution 2560x1440, got stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "TEST_PX1=1280") {
		t.Fatalf("expected PX1=1280 (scaled for 2560x1440), got stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "TEST_PY1=720") {
		t.Fatalf("expected PY1=720 (scaled for 2560x1440), got stderr:\n%s", stderrStr)
	}
}
