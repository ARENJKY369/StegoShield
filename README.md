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
