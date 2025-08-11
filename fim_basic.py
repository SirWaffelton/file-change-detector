import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

BASELINE_FILENAME = ".fim_baseline.json"
BLOCK_SIZE = 1024 * 1024  # 1 MiB chunks for hashing

def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 by streaming in chunks (memory friendly)."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(BLOCK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def list_files(root: Path):
    """Print all files under root, skipping the baseline file."""
    baseline_path = root / BASELINE_FILENAME
    for p in root.rglob("*"):
        if p.is_file():
            if p.resolve() == baseline_path.resolve():
                continue
            print(p.relative_to(root).as_posix())

def snapshot(root: Path) -> dict:
    """
    Build a snapshot of files under root:
    files: { "rel/path": {"size": int, "mtime": int, "sha256": str} }
    """
    baseline_path = root / BASELINE_FILENAME
    files = {}
    for p in root.rglob("*"):
        if p.is_file():
            if p.resolve() == baseline_path.resolve():
                continue
            st = p.stat()
            rel = p.relative_to(root).as_posix()
            files[rel] = {
                "size": st.st_size,
                "mtime": int(st.st_mtime),
                "sha256": compute_sha256(p),
            }
    return {
        "version": 2,  # v2 includes sha256
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "files": files,
    }

def save_baseline(root: Path, data: dict) -> Path:
    """Write the snapshot JSON to .fim_baseline.json at the folder root."""
    path = root / BASELINE_FILENAME
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path

def load_baseline(root: Path) -> dict:
    """Read and parse the baseline JSON."""
    path = root / BASELINE_FILENAME
    if not path.exists():
        raise FileNotFoundError(f"No baseline found at {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def compute_diff(baseline_data: dict, current_data: dict) -> dict:
    """
    Compare baseline vs current snapshots and return added/modified/deleted lists.
    Prefer hash comparison when both sides have 'sha256'; otherwise fall back to size/mtime.
    """
    base = baseline_data["files"]
    curr = current_data["files"]

    base_set = set(base.keys())
    curr_set = set(curr.keys())

    added = sorted(curr_set - base_set)
    deleted = sorted(base_set - curr_set)

    modified = []
    for rel in sorted(base_set & curr_set):
        b = base[rel]
        c = curr[rel]
        if "sha256" in b and "sha256" in c:
            if b["sha256"] != c["sha256"]:
                modified.append(rel)
        else:
            if b.get("size") != c.get("size") or b.get("mtime") != c.get("mtime"):
                modified.append(rel)

    return {"added": added, "modified": modified, "deleted": deleted}

def print_report(diff: dict):
    """Pretty-print the scan results."""
    print("Scan Report")
    print(f"- Added: {len(diff['added'])}")
    for rel in diff["added"]:
        print(f"  + {rel}")
    print(f"- Modified: {len(diff['modified'])}")
    for rel in diff["modified"]:
        print(f"  ~ {rel}")
    print(f"- Deleted: {len(diff['deleted'])}")
    for rel in diff["deleted"]:
        print(f"  - {rel}")

def prompt_folder() -> Path:
    folder = input("Folder path (e.g., C:\\dev\\fim_beginner\\lab): ").strip()
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}")
        raise SystemExit(1)
    return root

def main():
    print("FIM Beginner — Step 4 (hash-based detection)")
    print("1) List files")
    print("2) Create/Update baseline (includes SHA-256)")
    print("3) View baseline summary")
    print("4) Scan (compare with baseline)")
    choice = input("Choose 1/2/3/4: ").strip()

    root = prompt_folder()

    if choice == "1":
        print(f"Listing files under: {root}")
        list_files(root)

    elif choice == "2":
        data = snapshot(root)
        path = save_baseline(root, data)
        print(f"Baseline saved to: {path}")
        print(f"Files indexed: {len(data['files'])}")
        print("Tip: Re-run scan after updating the baseline to use hash-based detection.")

    elif choice == "3":
        try:
            data = load_baseline(root)
        except FileNotFoundError as e:
            print(e)
            return
        print(f"Baseline version: {data.get('version')}")
        print(f"Baseline created_at: {data.get('created_at')}")
        print(f"Files in baseline: {len(data['files'])}")
        any_file_meta = next(iter(data["files"].values()), {})
        has_hash = "sha256" in any_file_meta
        print(f"Hashes present: {has_hash}")
        shown = 0
        for rel, meta in data["files"].items():
            base_info = f"size={meta.get('size')}, mtime={meta.get('mtime')}"
            if "sha256" in meta:
                base_info += f", sha256={meta['sha256'][:8]}…"
            print(f"- {rel} ({base_info})")
            shown += 1
            if shown >= 5:
                break
        if len(data["files"]) > 5:
            print("...")

    elif choice == "4":
        try:
            baseline_data = load_baseline(root)
        except FileNotFoundError as e:
            print(e)
            return
        current_data = snapshot(root)
        diff = compute_diff(baseline_data, current_data)
        print_report(diff)
        if baseline_data.get("version") != 2:
            print("Note: Your baseline is version 1 (no hashes). For best accuracy, choose option 2 to recreate the baseline.")

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()