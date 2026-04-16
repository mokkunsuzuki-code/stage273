#!/usr/bin/env python3
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def verify_signature(review_path: Path, sig_path: Path, pubkey_path: Path):
    public_key = serialization.load_pem_public_key(pubkey_path.read_bytes())
    signature = base64.b64decode(sig_path.read_text(encoding="utf-8").strip())
    public_key.verify(signature, review_path.read_bytes())

def load_review(path: Path):
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    return {
        "path": path,
        "text": text,
        "data": data,
        "timestamp": data.get("timestamp_utc", ""),
        "review_id": data.get("review_id", path.stem),
    }

def main():
    review_dir = Path("review_records")
    pubkey_path = Path("keys/ed25519_public.pem")

    reviews = [load_review(p) for p in review_dir.glob("*.json")]
    if not reviews:
        raise SystemExit("No review records found.")

    reviews.sort(key=lambda r: (r["timestamp"], r["review_id"]))

    previous_expected = "GENESIS"
    for review in reviews:
        review_path = review["path"]
        data = review["data"]
        text = review["text"]

        sig_path = review_path.with_suffix(review_path.suffix + ".sig")
        if not sig_path.exists():
            raise SystemExit(f"Missing signature: {sig_path}")

        verify_signature(review_path, sig_path, pubkey_path)

        current_sha = sha256_text(text)
        sha_path = Path("out/review_chain") / f"review_{data['review_id']}.sha256"
        if not sha_path.exists():
            raise SystemExit(f"Missing sha file: {sha_path}")

        stored_sha = sha_path.read_text(encoding="utf-8").strip()
        if stored_sha != current_sha:
            raise SystemExit(f"SHA mismatch: {review_path}")

        if data["previous_review_sha256"] != previous_expected:
            raise SystemExit(
                f"Chain mismatch: {review_path} expected previous {previous_expected}, got {data['previous_review_sha256']}"
            )

        previous_expected = current_sha
        print(f"[OK] verified review: {review_path.name}")

    summary = {
        "stage": reviews[-1]["data"].get("stage", "unknown"),
        "verified_reviews": len(reviews),
        "final_chain_head": previous_expected,
        "result": "accept"
    }

    out_path = Path("out/review_chain/review_chain_verification.json")
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[OK] chain verification summary: {out_path}")

if __name__ == "__main__":
    main()
