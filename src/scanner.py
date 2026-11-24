import base64
import math
import os
import re
import time


def calculate_shannon_entropy(data: str) -> float:
  """Tính độ hỗn loạn Shannon: H(X) = - sum(p(x) * log2(p(x)))"""
  if not data:
    return 0.0
  length = len(data)
  char_counts = {}
  for char in data:
    char_counts[char] = char_counts.get(char, 0) + 1

  entropy = 0.0
  for count in char_counts.values():
    p = count / length
    entropy -= p * math.log2(p)
  return entropy


SECRET_PATTERNS = {
    "AWS Access Key ID": r"\b(AKIA[0-9A-Z]{16})\b",
    "AWS Secret Access Key": r"\b([0-9a-zA-Z/+]{40})\b",
    "GitHub Token": r"\b(ghp_[a-zA-Z0-9]{36})\b",
    "JWT Token": r"\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b",
    "RSA Private Key": r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----",
    "Generic High-Entropy Key": (
        r"(?i)(?:key|api|token|secret|password|auth)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"
    ),
}


def decode_evasions(text: str) -> list:
  """Giải mã các chuỗi bị che giấu bằng Base64, Hex, hoặc Unicode Escape."""
  decoded_results = []

  # 1. Base64 Decoding
  b64_matches = re.findall(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", text)
  for match in b64_matches:
    try:
      decoded_bytes = base64.b64decode(match, validate=True)
      decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
      if len(decoded_str) > 8:
        decoded_results.append((decoded_str, "Base64"))
    except Exception:
      pass

  # 2. Unicode Escape Decoding
  if "\\u" in text:
    try:
      decoded_str = text.encode("utf-8").decode("unicode-escape")
      if decoded_str != text:
        decoded_results.append((decoded_str, "Unicode Escape"))
    except Exception:
      pass

  # 3. Hex Decoding
  hex_matches = re.findall(r"(?:\\x[0-9a-fA-F]{2}){8,}", text)
  for match in hex_matches:
    try:
      clean_hex = match.replace("\\x", "")
      decoded_str = bytes.fromhex(clean_hex).decode("utf-8", errors="ignore")
      decoded_results.append((decoded_str, "Hex Encoded"))
    except Exception:
      pass

  return decoded_results


class SecretSentinel:

  def __init__(self, entropy_threshold: float = 4.2):
    self.entropy_threshold = entropy_threshold

  def scan_content(self, content: str, source_name: str = "memory") -> list:
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
      # Quét trực tiếp
      for secret_type, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, line):
          candidate = match.group(0)
          entropy = calculate_shannon_entropy(candidate)
          if (
              secret_type == "Generic High-Entropy Key"
              and entropy < self.entropy_threshold
          ):
            continue
          findings.append({
              "file": source_name,
              "line": line_num,
              "type": secret_type,
              "secret_snippet": candidate[:10] + "..." + candidate[-4:],
              "entropy": round(entropy, 2),
              "evasion": "None",
          })

      # Giải mã né tránh & Quét lại
      evasions = decode_evasions(line)
      for decoded_text, evasion_type in evasions:
        for secret_type, pattern in SECRET_PATTERNS.items():
          for match in re.finditer(pattern, decoded_text):
            candidate = match.group(0)
            entropy = calculate_shannon_entropy(candidate)
            findings.append({
                "file": source_name,
                "line": line_num,
                "type": secret_type,
                "secret_snippet": candidate[:10] + "..." + candidate[-4:],
                "entropy": round(entropy, 2),
                "evasion": evasion_type,
            })
    return findings

  def scan_directory(
      self, target_dir: str, ignore_dirs: list = None
  ) -> tuple[list, dict]:
    if ignore_dirs is None:
      ignore_dirs = [".git", "__pycache__", "node_modules", ".venv", "results"]

    all_findings = []
    total_files = 0
    total_bytes = 0
    start_time = time.time()

    for root, dirs, files in os.walk(target_dir):
      dirs[:] = [d for d in dirs if d not in ignore_dirs]
      for file in files:
        file_path = os.path.join(root, file)
        try:
          total_bytes += os.path.getsize(file_path)
          total_files += 1
          with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            findings = self.scan_content(f.read(), source_name=file_path)
            all_findings.extend(findings)
        except Exception:
          pass

    elapsed_time = time.time() - start_time
    throughput_mb = (
        (total_bytes / (1024 * 1024)) / elapsed_time if elapsed_time > 0 else 0.0
    )

    metrics = {
        "total_files": total_files,
        "total_bytes": total_bytes,
        "elapsed_time_sec": round(elapsed_time, 4),
        "throughput_mb_s": round(throughput_mb, 2),
        "total_secrets_found": len(all_findings),
    }
    return all_findings, metrics


if __name__ == "__main__":
  import sys

  target = sys.argv[1] if len(sys.argv) > 1 else "./tests/test_workspace"
  sentinel = SecretSentinel(entropy_threshold=4.2)
  findings, metrics = sentinel.scan_directory(target)

  print(f"[*] Quét hoàn tất thư mục: {target}")
  print(
      f"[*] Tổng số file: {metrics['total_files']} | Dung lượng:"
      f" {metrics['total_bytes']} bytes | Thời gian:"
      f" {metrics['elapsed_time_sec']}s"
  )

  if findings:
    print(f"\n[!] CẢNH BÁO: Phát hiện {len(findings)} rò rỉ bí mật!")
    for item in findings:
      print(
          f"  - {item['file']}:{item['line']} | {item['type']} |"
          f" {item['secret_snippet']} (Entropy: {item['entropy']}, Evasion:"
          f" {item['evasion']})"
      )
    sys.exit(1)  # Trả về exit code 1 để chặn Git commit hoặc CI/CD pipeline
  else:
    print("\n[+] SẠCH: Không phát hiện rò rỉ secret.")
    sys.exit(0)