package observability

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/jpeg"
	"image/png"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// ExtractAndProcessScreenshot 从远端 GUI 捕获输出中提取显式标记包裹的 Base64 图像载荷，
// 在解码像素前严格实施魔数分派（PNG/JPEG/WebP 零空导入）与解压炸弹尺寸守卫，并按最长边 1280px 等比双线性压缩为 JPEG。
func ExtractAndProcessScreenshot(rawStdout []byte) (ProcessedScreenshot, error) {
	b64Payload, err := extractMarkedPayload(string(rawStdout))
	if err != nil {
		return ProcessedScreenshot{}, err
	}
	if len(b64Payload) == 0 || len(b64Payload) > base64.StdEncoding.EncodedLen(maxScreenshotRawBytes) {
		return ProcessedScreenshot{}, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "screenshot_base64"), domi18n.Int("size", len(b64Payload)), domi18n.Int("limit", base64.StdEncoding.EncodedLen(maxScreenshotRawBytes)))
	}
	decoded, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil || len(decoded) == 0 || len(decoded) > maxScreenshotRawBytes {
		return ProcessedScreenshot{}, domi18n.WrapS(ErrScreenshotInvalid, err, domi18n.KeyCommonBase64DecodeFailed)
	}
	return ProcessScreenshotBytes(decoded)
}
func extractMarkedPayload(stdout string) (string, error) {
	_, rest, ok := strings.Cut(stdout, screenshotStartMarker)
	if !ok {
		return "", domi18n.EF(ErrScreenshotInvalid, domi18n.KeyUCObsScreenshotMarker)
	}
	body, _, ok := strings.Cut(rest, screenshotEndMarker)
	if !ok {
		return "", domi18n.EF(ErrScreenshotInvalid, domi18n.KeyUCObsScreenshotMarker)
	}
	return strings.TrimSpace(body), nil
}
func stripMarkedPayload(stdout string) string {
	before, rest, ok := strings.Cut(stdout, screenshotStartMarker)
	if !ok {
		return stdout
	}
	_, after, ok := strings.Cut(rest, screenshotEndMarker)
	if !ok {
		return stdout
	}
	return before + strings.TrimPrefix(strings.TrimPrefix(after, "\r"), "\n")
}

// ProcessScreenshotBytes 对原始图像字节执行纯 Go 零 CGO 魔数校验、防解压炸弹校验与最长边 1280px 等比 JPEG 压缩；
// 合法 WebP 在完整校验 RIFF/VP8/VP8L/VP8X 尺寸头后有界透传，不支持或受损图像严格失败关闭返回 ErrScreenshotInvalid。
func ProcessScreenshotBytes(raw []byte) (ProcessedScreenshot, error) {
	if len(raw) < 12 || len(raw) > maxScreenshotRawBytes {
		return ProcessedScreenshot{}, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "image"), domi18n.Int("size", len(raw)), domi18n.Int("limit", maxScreenshotRawBytes))
	}
	if isWebP(raw) {
		w, h, err := parseWebPDimensions(raw)
		if err != nil {
			return ProcessedScreenshot{}, err
		}
		return ProcessedScreenshot{MIMEType: "image/webp", Width: w, Height: h, OrigWidth: w, OrigHeight: h, Data: bytes.Clone(raw)}, nil
	}
	img, origW, origH, err := decodeGuardedImage(raw)
	if err != nil {
		return ProcessedScreenshot{}, err
	}
	dstW, dstH := calcScaledDimensions(origW, origH, screenshotTargetMaxEdge)
	scaled := img
	if dstW != origW || dstH != origH {
		scaled = downscaleBilinear(img, dstW, dstH)
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, scaled, &jpeg.Options{Quality: screenshotJPEGQuality}); err != nil {
		return ProcessedScreenshot{}, domi18n.WrapS(ErrScreenshotInvalid, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "jpeg_encode"))
	}
	return ProcessedScreenshot{MIMEType: "image/jpeg", Width: dstW, Height: dstH, OrigWidth: origW, OrigHeight: origH, Data: out.Bytes()}, nil
}
func isWebP(raw []byte) bool {
	return len(raw) >= 12 && bytes.Equal(raw[:4], []byte("RIFF")) && bytes.Equal(raw[8:12], []byte("WEBP"))
}
func isPNG(raw []byte) bool {
	return len(raw) >= 8 && bytes.Equal(raw[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
}
func isJPEG(raw []byte) bool {
	return len(raw) >= 3 && raw[0] == 0xff && raw[1] == 0xd8 && raw[2] == 0xff
}
func validateImageDimensions(w, h int) error {
	if w <= 0 || h <= 0 || w > maxScreenshotDim || h > maxScreenshotDim || int64(w)*int64(h) > maxScreenshotPixels {
		return domi18n.EF(ErrScreenshotInvalid, domi18n.KeyUCObsImageDimensions, domi18n.Int("width", w), domi18n.Int("height", h))
	}
	return nil
}

// parseWebPDimensions 纯 Go 解析 WebP RIFF 容器长度与 VP8/VP8L/VP8X 宽高头，阻断截断伪造载荷与像素炸弹。
func parseWebPDimensions(raw []byte) (int, int, error) {
	if len(raw) < 20 || !isWebP(raw) {
		return 0, 0, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "webp_header"))
	}
	riffSize := uint64(binary.LittleEndian.Uint32(raw[4:8]))
	chunkSize := uint64(binary.LittleEndian.Uint32(raw[16:20]))
	if riffSize < 12 || riffSize+8 > uint64(len(raw)) || 20+chunkSize > uint64(len(raw)) {
		return 0, 0, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "webp_chunk_size"))
	}
	var w, h int
	switch string(raw[12:16]) {
	case "VP8 ":
		if chunkSize < 10 || raw[20]&0x01 != 0 || raw[23] != 0x9d || raw[24] != 0x01 || raw[25] != 0x2a {
			return 0, 0, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "webp_vp8_header"))
		}
		w = int(binary.LittleEndian.Uint16(raw[26:28]) & 0x3fff)
		h = int(binary.LittleEndian.Uint16(raw[28:30]) & 0x3fff)
	case "VP8L":
		if chunkSize < 5 || raw[20] != 0x2f {
			return 0, 0, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "webp_vp8l_header"))
		}
		bits := binary.LittleEndian.Uint32(raw[21:25])
		w, h = int(bits&0x3fff)+1, int((bits>>14)&0x3fff)+1
	case "VP8X":
		if chunkSize < 10 {
			return 0, 0, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "webp_vp8x_header"))
		}
		w = int(uint32(raw[24])|uint32(raw[25])<<8|uint32(raw[26])<<16) + 1
		h = int(uint32(raw[27])|uint32(raw[28])<<8|uint32(raw[29])<<16) + 1
	default:
		return 0, 0, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "webp_chunk"), domi18n.BoundStr("value", string(raw[12:16])))
	}
	if err := validateImageDimensions(w, h); err != nil {
		return 0, 0, err
	}
	return w, h, nil
}

func decodeGuardedImage(raw []byte) (image.Image, int, int, error) {
	var cfg image.Config
	var err error
	var decodeFn func(*bytes.Reader) (image.Image, error)
	switch {
	case isPNG(raw):
		cfg, err = png.DecodeConfig(bytes.NewReader(raw))
		decodeFn = func(r *bytes.Reader) (image.Image, error) { return png.Decode(r) }
	case isJPEG(raw):
		cfg, err = jpeg.DecodeConfig(bytes.NewReader(raw))
		decodeFn = func(r *bytes.Reader) (image.Image, error) { return jpeg.Decode(r) }
	default:
		return nil, 0, 0, domi18n.EF(ErrScreenshotInvalid, domi18n.KeyUCObsImageFormat)
	}
	if err != nil {
		return nil, 0, 0, domi18n.WrapS(ErrScreenshotInvalid, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "image_header_decode"))
	}
	if err := validateImageDimensions(cfg.Width, cfg.Height); err != nil {
		return nil, 0, 0, err
	}
	img, err := decodeFn(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0, domi18n.WrapS(ErrScreenshotInvalid, err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "image_decode"))
	}
	b := img.Bounds()
	return img, b.Dx(), b.Dy(), nil
}

func calcScaledDimensions(w, h, maxEdge int) (int, int) {
	if w <= maxEdge && h <= maxEdge {
		return w, h
	}
	if w >= h {
		return maxEdge, max(h*maxEdge/w, 1)
	}
	return max(w*maxEdge/h, 1), maxEdge
}

// downscaleBilinear 执行纯 Go 零 CGO 双线性插值缩放，避免引入第三方图像缩放依赖并保持 UI 文本清晰。
func downscaleBilinear(src image.Image, dstW, dstH int) *image.RGBA {
	sb := src.Bounds()
	srcW, srcH, dst := sb.Dx(), sb.Dy(), image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	xr, yr := float64(srcW)/float64(dstW), float64(srcH)/float64(dstH)
	for y := range dstH {
		sy := (float64(y)+0.5)*yr - 0.5
		y0 := min(max(int(sy), 0), srcH-1)
		y1, wy := min(y0+1, srcH-1), min(max(sy-float64(y0), 0), 1)
		for x := range dstW {
			sx := (float64(x)+0.5)*xr - 0.5
			x0 := min(max(int(sx), 0), srcW-1)
			x1, wx := min(x0+1, srcW-1), min(max(sx-float64(x0), 0), 1)
			r, g, b := blend4(src, sb.Min.X+x0, sb.Min.Y+y0, sb.Min.X+x1, sb.Min.Y+y1, wx, wy)
			off := dst.PixOffset(x, y)
			dst.Pix[off], dst.Pix[off+1], dst.Pix[off+2], dst.Pix[off+3] = r, g, b, 0xff
		}
	}
	return dst
}
func blend4(src image.Image, x0, y0, x1, y1 int, wx, wy float64) (uint8, uint8, uint8) {
	r00, g00, b00, _ := src.At(x0, y0).RGBA()
	r10, g10, b10, _ := src.At(x1, y0).RGBA()
	r01, g01, b01, _ := src.At(x0, y1).RGBA()
	r11, g11, b11, _ := src.At(x1, y1).RGBA()
	w00, w10, w01, w11 := (1-wx)*(1-wy), wx*(1-wy), (1-wx)*wy, wx*wy
	mix := func(a, b, c, d uint32) uint8 {
		return uint8((float64(a)*w00 + float64(b)*w10 + float64(c)*w01 + float64(d)*w11) / 257.0)
	}
	return mix(r00, r10, r01, r11), mix(g00, g10, g01, g11), mix(b00, b10, b01, b11)
}
