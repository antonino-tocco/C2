from sqlmodel import Session

from .base_module import BaseModule


class NetworkScan(BaseModule):
    """Port scanner payload generator — produces OS-native scan commands."""

    def generate_payload(
        self,
        target_os: str,
        session: Session,
        target_id: str,
        **params,
    ) -> str:
        scan_target: str = params.get("scan_target", "127.0.0.1")
        ports: list[int] = params.get("ports", list(range(1, 1025)))
        timeout_ms: int = params.get("timeout_ms", 500)

        os_lower = target_os.lower()
        if "windows" in os_lower or "win" in os_lower:
            script = self._build_ps_script(scan_target, ports, timeout_ms)
            return self._wrap_powershell(script)
        else:
            script = self._build_bash_script(scan_target, ports, timeout_ms)
            return self._wrap_bash(script)

    @staticmethod
    def _build_ps_script(scan_target: str, ports: list[int], timeout_ms: int) -> str:
        port_list = ",".join(str(p) for p in ports)
        return f'''
$target = "{scan_target}"
$ports = @({port_list})
$timeout = {timeout_ms}
$open = @()
foreach ($p in $ports) {{
    try {{
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($target, $p, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($timeout, $false)
        if ($wait -and $tcp.Connected) {{
            $open += $p
        }}
        $tcp.Close()
    }} catch {{ }}
}}
$result = @{{ target = $target; open_ports = $open }} | ConvertTo-Json -Compress
Write-Output $result
'''

    @staticmethod
    def _build_bash_script(scan_target: str, ports: list[int], timeout_ms: int) -> str:
        timeout_sec = max(1, timeout_ms // 1000)
        port_list = " ".join(str(p) for p in ports)
        return f'''#!/bin/bash
TARGET="{scan_target}"
PORTS=({port_list})
TIMEOUT={timeout_sec}
OPEN=""
for PORT in "${{PORTS[@]}}"; do
    timeout $TIMEOUT bash -c "echo >/dev/tcp/$TARGET/$PORT" 2>/dev/null && OPEN="$OPEN $PORT"
done
OPEN=$(echo $OPEN | xargs)
if [ -z "$OPEN" ]; then
    PJSON="[]"
else
    PJSON="[$(echo $OPEN | tr ' ' '\\n' | sed 's/.*/"&"/' | paste -sd,)]"
fi
printf '{{"target":"%s","open_ports":%s}}\\n' "$TARGET" "$PJSON"
'''
