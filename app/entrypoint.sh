#!/bin/sh
set -e

mkdir -p /opt/flags

if [ ! -f /opt/flags/.generated ]; then
  python - <<'PY'
import secrets, os, json
from pathlib import Path

def mk(prefix):
    return f"VenD{{{prefix}_{secrets.token_hex(10)}}}"

def rand_segment():
    return secrets.token_hex(6)

flags = {
    'FLAG_SSTI':      mk('ssti'),
    'FLAG_JWT':       mk('jwtconf'),
    'FLAG_PICKLE':    mk('pickle'),
    'FLAG_RACE':      mk('race'),
    'FLAG_SQLI2':     mk('sqli2'),
    'FLAG_SVGXXE':    mk('svgxxe'),
    'FLAG_ZIPSLIP':   mk('zipslip'),
    'FLAG_YAML':      mk('yaml'),
    'FLAG_HOST':      mk('hostbypass'),
    'FLAG_CAPSTONE':  mk('vault'),
}

random_bits = {
    'SECRET_EXPORT_SEG': rand_segment(),
    'SECRET_CONFIG_SEG': rand_segment(),
    'SECRET_ADMIN_HOST': 'vault-' + rand_segment() + '.internal',
    'RSA_KID':           rand_segment(),
    'HMAC_SECRET':       secrets.token_hex(24),
    'FLASK_SECRET':      secrets.token_hex(24),
    'FLAG_DIR':          '/tmp/.vault/' + secrets.token_hex(8),
    'CSRF_PEPPER':       secrets.token_hex(16),
}

all_vars = {**flags, **random_bits}

with open('/opt/flags/.env', 'w') as fh:
    for k, v in all_vars.items():
        fh.write(f'{k}={v}\n')

os.makedirs(all_vars['FLAG_DIR'], exist_ok=True)
os.chmod('/tmp/.vault', 0o755)
os.chmod(all_vars['FLAG_DIR'], 0o755)

for name in ('SSTI', 'SVGXXE', 'ZIPSLIP'):
    p = Path(all_vars['FLAG_DIR']) / f'flag_{name.lower()}'
    p.write_text(flags[f'FLAG_{name}'] + '\n')
    p.chmod(0o644)

with open('/opt/flags/.answers.txt', 'w') as fh:
    fh.write('VAULTCORP HARD - trainer answer key\n')
    fh.write('generated at first container start\n\n')
    for k, v in all_vars.items():
        fh.write(f'{k:25s} = {v}\n')
os.chmod('/opt/flags/.answers.txt', 0o600)
os.chmod('/opt/flags/.env', 0o600)
PY
  touch /opt/flags/.generated
  echo "[entrypoint] randomised secrets generated"
fi

set -a
. /opt/flags/.env
set +a

mkdir -p "$FLAG_DIR"
chmod 755 /tmp/.vault "$FLAG_DIR"
echo "$FLAG_SSTI" > "$FLAG_DIR/flag_ssti"
echo "$FLAG_SVGXXE" > "$FLAG_DIR/flag_svgxxe"
echo "$FLAG_ZIPSLIP" > "$FLAG_DIR/flag_zipslip"
chmod 644 "$FLAG_DIR"/flag_*

python init_db.py
exec python app.py
