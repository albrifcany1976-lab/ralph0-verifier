import json
import os
from pathlib import Path
import subprocess
import sys
import time

if sys.argv[1] == 'timeout':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])
    print('PROBE_CHILD_STARTED', child.pid, flush=True)
    time.sleep(120)
elif sys.argv[1] == 'canary':
    assert os.getuid() != 0
    assert Path('/control/canary').read_text() == 'ralph0-protected-canary-v1\n'
    Path('/tmp/scratch').write_text('ok')
    assert Path('/tmp/scratch').read_text() == 'ok'
    denied = False
    try:
        with open('/control/canary', 'a') as f:
            f.write('changed')
    except PermissionError:
        denied = True
    except OSError as e:
        if e.errno == 30:
            denied = True
        else:
            raise
    assert denied
    assert not Path('/var/run/docker.sock').exists()
    assert not any(k.startswith(('GITHUB_', 'ACTIONS_')) for k in os.environ)
    print(json.dumps({'read': True, 'scratch': True, 'write_denied': True}))
else:
    raise RuntimeError('Unknown probe')
