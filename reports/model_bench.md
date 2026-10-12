# Model benchmark

Memory: 16.0 GB. Target median under 1.5s when possible.

| model | median_s | p95_s | json_success |
| --- | ---: | ---: | ---: |
| llama3.2:1b | 0.49 | 0.83 | 100% |
| qwen2.5:1.5b | 0.50 | 0.89 | 100% |
| gemma2:2b | 0.76 | 1.48 | 100% |

**Primary analyst:** `llama3.2:1b`
**Cross-check models:** `qwen2.5:1.5b`, `gemma2:2b`

## Kokoro / local TTS (60-word message)

- backend: say
- seconds: 1.98
- ok: True
- target: under 2.0s
