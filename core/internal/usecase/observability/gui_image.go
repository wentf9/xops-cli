package observability

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"strings"
)

// ExtractAndProcessScreenshot 从远端 GUI 捕获输出中提取显式标记包裹的 Base64 图像载荷，
// 在解码像素前严格实施魔数分派（PNG/JPEG/WebP 零空导入）与解压炸弹尺寸守卫，并按最长边 1280px 等比双线性压缩为 JPEG。
func ExtractAndProcessScreenshot(rawStdout []byte) (ProcessedScreenshot, error) {
	b64Payload, err := extractMarkedPayload(string(rawStdout))
	if err != nil {
		return ProcessedScreenshot{}, err
	}
	maxEncodedLen := base64.StdEncoding.EncodedLen(maxScreenshotRawBytes)
	if len(b64Payload) == 0 || len(b64Payload) > maxEncodedLen {
		return ProcessedScreenshot{}, fmt.Errorf("%w: Base64 截图载荷为空或超过字节上限", ErrScreenshotInvalid)
	}
	decoded, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil || len(decoded) == 0 || len(decoded) > maxScreenshotRawBytes {
		return ProcessedScreenshot{}, fmt.Errorf("%w: Base64 解码失败或超限", ErrScreenshotInvalid)
	}
	return ProcessScreenshotBytes(decoded)
}

func extractMarkedPayload(stdout string) (string, error) {
	startIdx := strings.Index(stdout, screenshotStartMarker)
	if startIdx < 0 {
		return "", fmt.Errorf("%w: 缺少截图起始标记", ErrScreenshotInvalid)
	}
	rest := stdout[startIdx+len(screenshotStartMarker):]
	endIdx := strings.Index(rest, screenshotEndMarker)
	if endIdx < 0 {
		return "", fmt.Errorf("%w: 截图载荷截断（缺少结束标记）", ErrScreenshotInvalid)
	}
	return strings.TrimSpace(rest[:endIdx]), nil
}

// ProcessScreenshotBytes 对原始图像字节执行纯 Go 零 CGO 魔数校验、防解压炸弹校验与最长边 1280px 等比 JPEG 压缩；
// 合法 WebP 直接有界透传，不支持或受损图像严格失败关闭返回 ErrScreenshotInvalid。
func ProcessScreenshotBytes(raw []byte) (ProcessedScreenshot, error) {
	if len(raw) < 12 || len(raw) > maxScreenshotRawBytes {
		return ProcessedScreenshot{}, fmt.Errorf("%w: 图像字节长度非法", ErrScreenshotInvalid)
	}
	if isWebP(raw) {
		return ProcessedScreenshot{MIMEType: "image/webp", Data: bytes.Clone(raw)}, nil
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
		return ProcessedScreenshot{}, fmt.Errorf("%w: JPEG 编码失败: %w", ErrScreenshotInvalid, err)
	}
	return ProcessedScreenshot{
		MIMEType: "image/jpeg", Width: dstW, Height: dstH,
		OrigWidth: origW, OrigHeight: origH, Data: out.Bytes(),
	}, nil
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
		return nil, 0, 0, fmt.Errorf("%w: 仅支持 PNG / JPEG / WebP 图像格式", ErrScreenshotInvalid)
	}
	if err != nil {
		return nil, 0, 0, fmt.Errorf("%w: 图像头解析失败: %w", ErrScreenshotInvalid, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxScreenshotDim || cfg.Height > maxScreenshotDim || int64(cfg.Width)*int64(cfg.Height) > maxScreenshotPixels {
		return nil, 0, 0, fmt.Errorf("%w: 图像尺寸 %dx%d 超过安全上限", ErrScreenshotInvalid, cfg.Width, cfg.Height)
	}
	img, err := decodeFn(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("%w: 图像解码失败: %w", ErrScreenshotInvalid, err)
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
	srcW, srcH := sb.Dx(), sb.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	xRatio, yRatio := float64(srcW)/float64(dstW), float64(srcH)/float64(dstH)
	for y := range dstH {
		sy := (float64(y)+0.5)*yRatio - 0.5
		y0 := min(max(int(sy), 0), srcH-1)
		y1 := min(y0+1, srcH-1)
		wy := min(max(sy-float64(y0), 0), 1)
		for x := range dstW {
			sx := (float64(x)+0.5)*xRatio - 0.5
			x0 := min(max(int(sx), 0), srcW-1)
			x1 := min(x0+1, srcW-1)
			wx := min(max(sx-float64(x0), 0), 1)
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
