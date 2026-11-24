import base64
import os
import random
import sys
import time
import matplotlib.pyplot as plt
import pandas as pd

# Import scanner từ thư mục src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.scanner import SecretSentinel


def generate_random_string(
    length: int,
    chars: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
) -> str:
  return "".join(random.choice(chars) for _ in range(length))


def create_dataset(num_samples: int = 10000, seed: int = 42) -> list:
  random.seed(seed)
  dataset = []
  half = num_samples // 2

  # Sinh mẫu chứa Secret (Positive)
  for _ in range(half):
    kind = random.choice([
        "aws_id",
        "aws_sec",
        "gh_token",
        "jwt",
        "rsa",
        "generic_key",
        "base64_aws",
        "unicode_gh",
    ])
    if kind == "aws_id":
      line = (
          "AWS_KEY ="
          f" 'AKIA{generate_random_string(16, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')}'"
      )
    elif kind == "aws_sec":
      line = (
          "aws_secret_access_key ="
          f" '{generate_random_string(40, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+')}'"
      )
    elif kind == "gh_token":
      line = f'export GITHUB_TOKEN="ghp_{generate_random_string(36)}"'
    elif kind == "jwt":
      line = (
          "auth_header = 'Bearer"
          f" eyJ{generate_random_string(20)}.eyJ{generate_random_string(30)}.{generate_random_string(25)}'"
      )
    elif kind == "rsa":
      line = "-----BEGIN RSA PRIVATE KEY-----"
    elif kind == "generic_key":
      line = f"api_secret_key = '{generate_random_string(32)}'"
    elif kind == "base64_aws":
      raw = (
          "AKIA"
          + generate_random_string(16, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
      )
      line = f"# Secret: {base64.b64encode(raw.encode()).decode()}"
    elif kind == "unicode_gh":
      token = "ghp_" + generate_random_string(36)
      escaped = "".join(f"\\u{ord(c):04x}" for c in token)
      line = f"const token = '{escaped}';"
    dataset.append({"content": line, "has_secret": True})

  # Sinh mẫu mã nguồn sạch (Negative)
  clean_templates = [
      (
          "function calculateTotal(items) { return items.reduce((a, b) => a +"
          " b, 0); }"
      ),
      "import os, sys, math, time, json",
      "SELECT * FROM users WHERE status = 'active' AND age > 18;",
      "const MAX_RETRY_COUNT = 5;",
      "logger.info('User successfully logged in')",
  ]
  for _ in range(half):
    noise = generate_random_string(8, "abcdefghijklmnopqrstuvwxyz")
    dataset.append({
        "content": f"// {noise}\n{random.choice(clean_templates)}",
        "has_secret": False,
    })

  random.shuffle(dataset)
  return dataset


if __name__ == "__main__":
  os.makedirs("../results", exist_ok=True)
  dataset = create_dataset(10000)
  scanner = SecretSentinel(entropy_threshold=3.5)

  tp = fp = tn = fn = 0
  start_time = time.time()

  for item in dataset:
    detected = len(scanner.scan_content(item["content"])) > 0
    actual = item["has_secret"]
    if detected and actual:
      tp += 1
    elif detected and not actual:
      fp += 1
    elif not detected and not actual:
      tn += 1
    elif not detected and actual:
      fn += 1

  elapsed = time.time() - start_time
  precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
  recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
  f1 = (
      2 * (precision * recall) / (precision + recall)
      if (precision + recall) > 0
      else 0
  )
  accuracy = ((tp + tn) / len(dataset)) * 100

  # Lưu kết quả ra CSV
  df_res = pd.DataFrame([{
      "Total_Samples": len(dataset),
      "TP": tp,
      "FP": fp,
      "TN": tn,
      "FN": fn,
      "Accuracy (%)": round(accuracy, 2),
      "Precision (%)": round(precision, 2),
      "Recall (%)": round(recall, 2),
      "F1-Score (%)": round(f1, 2),
      "Total_Time (s)": round(elapsed, 4),
      "Avg_Latency (ms)": round((elapsed / len(dataset)) * 1000, 4),
  }])
  df_res.to_csv("../results/benchmark_10k_summary.csv", index=False)
  print(df_res.to_string(index=False))