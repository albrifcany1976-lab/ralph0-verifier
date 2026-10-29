"""Seal transport bytes, not authority. Re-run after a reviewed repository edit."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
def payload():
    return sorted(p for p in ROOT.rglob('*') if p.is_file() and
                  not any(x in ('.git', '__pycache__') for x in p.relative_to(ROOT).parts) and
                  p.name not in ('SHA256SUMS', 'MANIFEST.json'))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--check', action='store_true'); args = parser.parse_args()
    files = payload()
    manifest = {str(p.relative_to(ROOT)): {'sha256': sha(p), 'bytes': p.stat().st_size} for p in files}
    path = ROOT/'MANIFEST.json'
    if args.check:
        assert json.loads(path.read_text()) == manifest, 'Manifest content mismatch'
    else:
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    sums = ''.join(sha(p)+'  '+str(p.relative_to(ROOT))+'\n' for p in sorted(files+[path]))
    if args.check:
        assert (ROOT/'SHA256SUMS').read_text() == sums, 'Checksum list mismatch'
    else:
        (ROOT/'SHA256SUMS').write_text(sums)
    print('Package integrity OK: '+str(len(files))+' payload files')
