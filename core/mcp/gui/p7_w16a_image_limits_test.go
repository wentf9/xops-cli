package gui

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"
)

// buildSyntheticPNGHeader creates a tiny valid PNG header (signature + IHDR
// chunk with valid CRC32 + IEND) declaring arbitrary dimensions without
// allocating pixel memory.
func buildSyntheticPNGHeader(width, height uint32) []byte {
	var buf bytes.Buffer
	// Standard 8-byte PNG signature.
	buf.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})

	// IHDR chunk payload (13 bytes): width, height, bit depth 8, color type 2 (RGB).
	var ihdr [13]byte
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8 // bit depth
	ihdr[9] = 2 // truecolor RGB

	writePNGChunk(&buf, "IHDR", ihdr[:])
	writePNGChunk(&buf, "IEND", nil)
	return buf.Bytes()
}

func writePNGChunk(buf *bytes.Buffer, chunkType string, data []byte) {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(data)))
	buf.Write(lenBytes[:])
	buf.WriteString(chunkType)
	buf.Write(data)

	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte(chunkType))
	_, _ = crc.Write(data)
	var crcBytes [4]byte
	binary.BigEndian.PutUint32(crcBytes[:], crc.Sum32())
	buf.Write(crcBytes[:])
}

func TestP7W16a_AB16L1_ProcessImagePreDecodeDimensionAndPixelCeiling(t *testing.T) {
	tests := []struct {
		name       string
		width      uint32
		height     uint32
		wantSubstr string
	}{
		{
			name:       "decompression_bomb_46340x46340",
			width:      46340,
			height:     46340,
			wantSubstr: "exceed maximum allowed limits",
		},
		{
			name:       "width_exceeds_16384",
			width:      16385,
			height:     1,
			wantSubstr: "exceed maximum allowed limits",
		},
		{
			name:       "height_exceeds_16384",
			width:      1,
			height:     16385,
			wantSubstr: "exceed maximum allowed limits",
		},
		{
			name:       "pixels_exceed_64_million_within_edge_limit",
			width:      10000,
			height:     10000,
			wantSubstr: "exceed maximum allowed limits",
		},
		{
			name:       "zero_dimension_rejected",
			width:      0,
			height:     100,
			wantSubstr: "decode image config",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildSyntheticPNGHeader(tc.width, tc.height)
			start := time.Now()
			out, mimeType, err := ProcessImage(raw)
			elapsed := time.Since(start)

			if err == nil {
				t.Fatalf("ProcessImage(%dx%d) succeeded unexpectedly (mime=%q len=%d)", tc.width, tc.height, mimeType, len(out))
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("ProcessImage(%dx%d) err = %q, want substring %q", tc.width, tc.height, err.Error(), tc.wantSubstr)
			}
			if elapsed > 50*time.Millisecond {
				t.Fatalf("ProcessImage(%dx%d) took %v, want <50ms pre-decode rejection", tc.width, tc.height, elapsed)
			}
		})
	}

	t.Run("valid_small_png_still_processes", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, 16, 16))
		img.SetRGBA(0, 0, color.RGBA{R: 10, G: 20, B: 30, A: 255})
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			t.Fatalf("png.Encode: %v", err)
		}
		out, mimeType, err := ProcessImage(buf.Bytes())
		if err != nil || mimeType != "image/jpeg" || len(out) == 0 {
			t.Fatalf("ProcessImage(valid 16x16) = (len=%d, mime=%q, err=%v)", len(out), mimeType, err)
		}
	})
}
