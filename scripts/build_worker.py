#!/usr/bin/env python3
"""Compile the shared verifier into Wasm and generate its JavaScript bindings."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    env = os.environ.copy()
    # Apple's clang lacks the Wasm backend required by secp256k1-sys.
    if sys.platform == 'darwin':
        for prefix in ('/opt/homebrew/opt/llvm/bin', '/usr/local/opt/llvm/bin'):
            if Path(prefix, 'clang').exists():
                env.setdefault('CC_wasm32_unknown_unknown', f'{prefix}/clang')
                env.setdefault('AR_wasm32_unknown_unknown', f'{prefix}/llvm-ar')
                break
    bindgen = shutil.which('wasm-bindgen') or str(ROOT / 'target/wasm-tools/bin/wasm-bindgen')
    version = subprocess.check_output([bindgen, '--version'], text=True).strip()
    if version != 'wasm-bindgen 0.2.129':
        raise SystemExit('Install wasm-bindgen-cli 0.2.129 to match worker/wasm/Cargo.lock')
    target = ROOT / 'worker/wasm/target'
    subprocess.run(['cargo', 'build', '--manifest-path', 'worker/wasm/Cargo.toml',
                    '--target-dir', str(target), '--target', 'wasm32-unknown-unknown',
                    '--release', '--locked'], cwd=ROOT, env=env, check=True)
    subprocess.run([bindgen, '--target', 'web', '--out-dir', 'worker/pkg',
                    str(target / 'wasm32-unknown-unknown/release/ironwood_verifier_wasm.wasm')],
                   cwd=ROOT, check=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    (ROOT / 'worker/pkg/source.mjs').write_text(f'export const commit = {json.dumps(commit)};\n')


if __name__ == '__main__':
    main()
