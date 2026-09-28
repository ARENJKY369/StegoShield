# StegoShield

> **Implementation status:** this repository is being built in numbered stages. This
> initial outline and the `core` and `crypto` packages are present; the remaining
> modules listed below are added in subsequent stages.

## Purpose

StegoShield is an offline toolkit that helps at-risk users communicate covertly
**and** helps organizations detect, explain, and neutralize
steganography-based data leaks and payload smuggling. Files such as photos,
audio, and text can secretly carry data that bypasses filters which only inspect
file type or known malware signatures. It is a steganalysis scanner, **not** a
full antivirus.

## Planned architecture

```text
StegoShield/
├── README.md
├── src/
│   ├── core/       # shared Stego API, payload header, bit helpers
│   ├── crypto/     # AES-256-GCM and PBKDF2 password processing
│   ├── image/      # PNG/BMP LSB embedding, metrics, difference imagery
│   ├── audio/      # 16-bit little-endian PCM WAV LSB embedding
│   ├── text/       # zero-width Unicode embedding and detection
│   ├── eof/        # PNG trailing-byte and text-chunk fixtures
│   ├── analysis/   # explainable scanning, heatmaps, batch reports
│   ├── sanitize/   # non-destructive carrier cleaning
│   ├── decoy/      # plausible-deniability dual-message workflow
│   ├── network/    # localhost timing-channel simulation and analysis
│   ├── eval/       # runtime detection evaluation
│   ├── ui/          # AWT application
│   └── test/        # JDK-only self-tests
└── out/            # generated compiler output; not source-controlled
```

## Implemented foundation

- `core.Stego<C>`: generic capacity, embed, and extract contract.
- `core.Payload`: versioned `SSHD` header with length and CRC32 validation.
- `core.BitUtil`: bounds-checked, most-significant-bit-first bit helpers.
- `crypto.CryptoUtil`: AES-256-GCM with PBKDF2WithHmacSHA256, 65,536
  iterations, a 16-byte salt, and a 12-byte IV. Output is
  `salt | IV | ciphertext-and-tag`; mutable password arrays and derived key
  bytes are cleared after use.
- `image.LSBImageStego`: RGB-channel LSB embedding with a 32-bit length header,
  PNG/BMP carrier validation, sequential or password-scattered placement, and
  lossless PNG-only output.
- `image.ImageMetrics`: RGB MSE, PSNR, and amplified visual difference images.
- `audio.LSBAudioStego`: 16-bit signed little-endian PCM WAV LSB embedding
  while preserving the source AudioFormat on output.
- `text.ZeroWidthStego`: U+200B/U+200C text embedding plus detection and safe
  stripping of U+200B–U+200D, U+2060, and U+FEFF.
- `eof`: PNG IEND-trailing-byte and ImageIO tEXt metadata payload fixtures for
  exercising scanner and sanitizer behaviour.
- `analysis`: an explainable 0–100 risk scanner, extraction attempts, PNG/JPEG
  trailing-data checks, file-signature checks, image/WAV LSB indicators,
  invisible-Unicode detection, PNG metadata sizing, batch scanning, UTF-8
  report export, and an AWT LSB heatmap canvas.
- `sanitize.StegoCleaner`: a non-destructive cleaner that re-encodes images,
  randomizes LSBs with SecureRandom, strips invisible Unicode, randomizes WAV
  sample LSBs, and re-scans every output.
- `decoy.DecoyMode`: fixed-size decoy/real AES-GCM containers with real data
  scattered into random-looking padding; the final README documents its limits.
- `network`: a localhost-only 50 ms/150 ms timing-channel simulation with
  timeout-bound sockets, background receive callbacks, an inter-arrival
  histogram, and bimodality/regularity analysis.
- `eval.EvaluationRunner`: runtime corpus generation from clean PNG/BMP images,
  measured 10/25/50/100% LSB detection, appended-data and wrong-extension
  cases, false-positive measurement, console output, and UTF-8 table export.

## Full README sections to be completed with the final implementation

1. Problem statement and intended defensive/privacy use
2. Architecture and carrier formats
3. Build and run instructions for a plain JDK 17
4. Hide, extract, scan, clean, batch, and evaluation usage
5. Explainable risk-scoring methodology and thresholds
6. Decoy-mode design and its security limits
7. Limitations, ethics, authorization, and privacy guidance
8. Future work: MP4/video codecs, live packet capture, MP3 support, and JPEG
   DCT steganography are deliberately out of scope
9. Viva-style questions and answers
10. Public API inventory, assumptions, and exact self-test commands

## Security and ethics

Use StegoShield only on files you own or are explicitly authorized to analyze.
It is designed for offline privacy and defensive security. It does not replace
malware protection, forensic review, or legal/organizational policy.
