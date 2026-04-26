using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CrashSwitch
{
    public sealed class Simulator : IDisposable
    {
        private readonly HotspotManager _hotspot;
        private readonly ConcurrentDictionary<string, DeviceRecord> _devices
            = new ConcurrentDictionary<string, DeviceRecord>();

        private PacketSniffer? _sniffer;
        private FlowWorker?    _activeFlow;
        private string?        _deviceIp;
        private string?        _serverIp;
        private volatile bool  _cutoffEnabled;
        private volatile bool  _running;
        private readonly object _flowLock = new object();

        // Countdown
        private int     _countdownSec  = 0;
        private bool    _countdownActive = false;
        private Timer?  _countdownTimer;

        // IFTTT
        private string? _iftttKey;
        private static readonly string ConfigPath =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "CrashSwitch", "config.json");

        private readonly AuthContext _auth;

        public Simulator(AuthContext auth)
        {
            _auth    = auth;
            _hotspot = new HotspotManager();
            LoadConfig();
        }

        // ── Config (IFTTT key persistence) ────────────────────────────────────
        private void LoadConfig()
        {
            try
            {
                if (!File.Exists(ConfigPath)) return;
                var json = File.ReadAllText(ConfigPath);
                var doc  = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("iftttKey", out var k))
                    _iftttKey = k.GetString();
            }
            catch { }
        }

        private void SaveConfig()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
                var obj = JsonSerializer.Serialize(new { iftttKey = _iftttKey ?? "" });
                File.WriteAllText(ConfigPath, obj);
            }
            catch { }
        }

        // ── Entry point ───────────────────────────────────────────────────────
        public void Run()
        {
            if (!IsAdmin())
            {
                Console.WriteLine("Must run as Administrator.");
                Console.ReadKey(true);
                return;
            }

            EnableAnsi();
            Console.Title = "CRASH SWITCH";
            _running = true;

            Console.Clear();
            PrintLogo();
            Terminal.Info("Starting hotspot...");
            string hsErr;
            if (!_hotspot.Start(out hsErr))
            {
                Terminal.Error($"Hotspot error: {hsErr}");
                Console.ReadKey(true);
                return;
            }

            _sniffer = new PacketSniffer(_hotspot, _devices);
            string snErr;
            if (!_sniffer.Start(out snErr))
                Terminal.Warn($"Sniffer: {snErr}");

            Terminal.Info("Waiting for device to connect...");
            WaitForDevice();

            // IFTTT polling thread
            if (!string.IsNullOrEmpty(_iftttKey))
                new Thread(IftttPoller) { IsBackground = true, Name = "IFTTT" }.Start();

            // Spacebar listener
            new Thread(SpacebarListener) { IsBackground = true, Name = "Space" }.Start();

            MenuLoop();
        }

        // ── Device detection ──────────────────────────────────────────────────
        private void WaitForDevice()
        {
            for (int i = 0; i < 30; i++)
            {
                _deviceIp = GetConnectedDevice();
                if (_deviceIp != null)
                {
                    Terminal.Ok($"Device detected: {_deviceIp}");
                    Thread.Sleep(500);
                    return;
                }
                Thread.Sleep(1000);
            }
            Terminal.Warn("No device detected yet.");
        }

        private string? GetConnectedDevice()
        {
            foreach (var kv in _devices)
                if (_hotspot.IsHotspotIp(kv.Key)) return kv.Key;
            return null;
        }

        // ── Spacebar ──────────────────────────────────────────────────────────
        private void SpacebarListener()
        {
            while (_running)
            {
                try
                {
                    if (Console.KeyAvailable)
                    {
                        var k = Console.ReadKey(intercept: true);
                        if (k.Key == ConsoleKey.Spacebar) ToggleCutoff();
                    }
                    else Thread.Sleep(50);
                }
                catch { Thread.Sleep(100); }
            }
        }

        // ── Cutoff toggle + 13s countdown ─────────────────────────────────────
        private void ToggleCutoff()
        {
            if (_deviceIp == null || _serverIp == null) return;

            lock (_flowLock)
            {
                if (_cutoffEnabled)
                {
                    DisableCutoff();
                }
                else
                {
                    EnableCutoff();
                }
            }
            DrawMenu();
        }

        private void EnableCutoff()
        {
            // Stop any existing flow/timer
            _countdownTimer?.Dispose();
            _activeFlow?.Stop();

            var key    = new FlowKey(_deviceIp!, _serverIp!);
            var worker = new FlowWorker(key, Profiles.Cutoff);
            string err;
            if (!worker.Start(out err))
            {
                Terminal.Error($"Cutoff failed: {err}");
                return;
            }

            _activeFlow      = worker;
            _cutoffEnabled   = true;
            _countdownSec    = 13;
            _countdownActive = true;

            // Fire IFTTT enabled event
            if (!string.IsNullOrEmpty(_iftttKey))
                _ = FireIftttAsync("crash_switch_enabled");

            // Countdown timer — ticks every second
            _countdownTimer = new Timer(_ =>
            {
                lock (_flowLock)
                {
                    if (!_countdownActive) return;
                    _countdownSec--;
                    if (_countdownSec <= 0)
                    {
                        DisableCutoff();
                        if (!string.IsNullOrEmpty(_iftttKey))
                            _ = FireIftttAsync("crash_switch_disabled");
                    }
                }
                DrawMenu();
            }, null, 1000, 1000);
        }

        private void DisableCutoff()
        {
            _countdownTimer?.Dispose();
            _countdownTimer  = null;
            _countdownActive = false;
            _countdownSec    = 0;
            _activeFlow?.Stop();
            _activeFlow      = null;
            _cutoffEnabled   = false;
        }

        // ── IFTTT ─────────────────────────────────────────────────────────────
        private void IftttPoller()
        {
            // Poll IFTTT Webhooks reverse trigger (value service)
            // Not standard IFTTT — instead we use a simple polling endpoint
            // that the user sets up via IFTTT -> Webhooks -> GET request
            // For now this fires outgoing events only (triggers IFTTT applets)
            while (_running) Thread.Sleep(5000);
        }

        private async Task FireIftttAsync(string eventName)
        {
            if (string.IsNullOrEmpty(_iftttKey)) return;
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                var url = $"https://maker.ifttt.com/trigger/{eventName}/with/key/{_iftttKey}";
                await client.PostAsync(url, null);
            }
            catch { }
        }

        // ── Menu loop ─────────────────────────────────────────────────────────
        private void MenuLoop()
        {
            while (_running)
            {
                DrawMenu();
                try
                {
                    var k = Console.ReadKey(intercept: true);
                    switch (k.Key)
                    {
                        case ConsoleKey.D1: case ConsoleKey.NumPad1: AutoDetectServer(); break;
                        case ConsoleKey.D2: case ConsoleKey.NumPad2: ManualPickServer(); break;
                        case ConsoleKey.D3: case ConsoleKey.NumPad3: ConfigureIfttt(); break;
                        case ConsoleKey.Spacebar: ToggleCutoff(); break;
                        case ConsoleKey.Q: Dispose(); return;
                    }
                }
                catch { }
            }
        }

        private void DrawMenu()
        {
            Console.Clear();
            PrintLogo();

            _deviceIp ??= GetConnectedDevice();
            Console.WriteLine();
            Console.WriteLine($"  {"Device:",-12} {(_deviceIp != null ? $"\x1b[92m{_deviceIp}\x1b[0m" : "\x1b[93mWaiting...\x1b[0m")}");
            Console.WriteLine($"  {"Server:",-12} {(_serverIp  != null ? $"\x1b[92m{_serverIp}\x1b[0m"  : "\x1b[93mNot selected\x1b[0m")}");

            // IFTTT indicator
            var iftttStatus = !string.IsNullOrEmpty(_iftttKey) ? "\x1b[92m●\x1b[0m Configured" : "\x1b[2m○ Not configured\x1b[0m";
            Console.WriteLine($"  {"IFTTT:",-12} {iftttStatus}");

            Console.WriteLine();

            // Cutoff status with countdown
            if (_deviceIp == null || _serverIp == null)
            {
                Console.WriteLine($"  {"Cutoff:",-12} \x1b[2mSelect a server first\x1b[0m");
            }
            else if (_cutoffEnabled)
            {
                var bar      = BuildCountdownBar(_countdownSec, 13);
                var secLabel = $"\x1b[93m{_countdownSec,2}s\x1b[0m remaining";
                Console.WriteLine($"  {"Cutoff:",-12} \x1b[91m\x1b[1mENABLED\x1b[0m   {bar} {secLabel}");
            }
            else
            {
                Console.WriteLine($"  {"Cutoff:",-12} \x1b[92m\x1b[1mDISABLED\x1b[0m  \x1b[2m(press SPACE to enable)\x1b[0m");
            }

            Console.WriteLine();
            Console.WriteLine("  \x1b[96m┌──────────────────────────────────────────────┐\x1b[0m");
            Console.WriteLine("  \x1b[96m│\x1b[0m  \x1b[97m[1]\x1b[0m  Auto-detect game server               \x1b[96m│\x1b[0m");
            Console.WriteLine("  \x1b[96m│\x1b[0m  \x1b[97m[2]\x1b[0m  Pick server manually                  \x1b[96m│\x1b[0m");
            Console.WriteLine("  \x1b[96m│\x1b[0m  \x1b[97m[3]\x1b[0m  Configure IFTTT                       \x1b[96m│\x1b[0m");
            Console.WriteLine("  \x1b[96m│\x1b[0m  \x1b[97m[SPACE]\x1b[0m Toggle cutoff on/off               \x1b[96m│\x1b[0m");
            Console.WriteLine("  \x1b[96m│\x1b[0m  \x1b[97m[Q]\x1b[0m  Quit                                  \x1b[96m│\x1b[0m");
            Console.WriteLine("  \x1b[96m└──────────────────────────────────────────────┘\x1b[0m");
            Console.WriteLine();
        }

        private static string BuildCountdownBar(int remaining, int total)
        {
            int width   = 13;
            int filled  = (int)Math.Round((double)remaining / total * width);
            var bar     = new System.Text.StringBuilder();
            bar.Append("\x1b[91m[");
            bar.Append('█', filled);
            bar.Append(' ', width - filled);
            bar.Append("]\x1b[0m");
            return bar.ToString();
        }

        // ── IFTTT config ──────────────────────────────────────────────────────
        private void ConfigureIfttt()
        {
            Console.Clear();
            PrintLogo();
            Console.WriteLine();
            Terminal.Header("IFTTT Configuration");
            Console.WriteLine();
            Console.WriteLine("  IFTTT Webhooks lets you trigger actions on your phone");
            Console.WriteLine("  when the cutoff is enabled or disabled.");
            Console.WriteLine();
            Console.WriteLine("  Setup:");
            Console.WriteLine("  1. Go to https://ifttt.com and create a free account");
            Console.WriteLine("  2. Search for 'Webhooks' and connect it");
            Console.WriteLine("  3. Go to https://ifttt.com/maker_webhooks -> Documentation");
            Console.WriteLine("  4. Copy your key from that page");
            Console.WriteLine("  5. Create applets using event names:");
            Console.WriteLine("     \x1b[93mcrash_switch_enabled\x1b[0m  — fires when cutoff turns ON");
            Console.WriteLine("     \x1b[93mcrash_switch_disabled\x1b[0m — fires when cutoff turns OFF");
            Console.WriteLine();

            if (!string.IsNullOrEmpty(_iftttKey))
            {
                Console.WriteLine($"  Current key: \x1b[92m{_iftttKey}\x1b[0m");
                Console.WriteLine();
                Console.WriteLine("  [1] Update key    [2] Remove key    [Enter] Cancel");
                Console.Write("  Choice: ");
                var c = Console.ReadKey(intercept: true);
                Console.WriteLine();
                if (c.Key == ConsoleKey.D2)
                {
                    _iftttKey = null;
                    SaveConfig();
                    Terminal.Ok("IFTTT key removed.");
                    Thread.Sleep(1000);
                    return;
                }
                else if (c.Key != ConsoleKey.D1)
                    return;
            }

            Console.Write("  Enter your IFTTT Webhook key: ");
            var key = Console.ReadLine()?.Trim() ?? "";
            if (string.IsNullOrEmpty(key))
            {
                Terminal.Warn("No key entered. Cancelled.");
                Thread.Sleep(1000);
                return;
            }

            _iftttKey = key;
            SaveConfig();

            // Test the webhook
            Console.WriteLine();
            Terminal.Info("Testing webhook...");
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                var url  = $"https://maker.ifttt.com/trigger/crash_switch_test/with/key/{_iftttKey}";
                var resp = client.PostAsync(url, null).GetAwaiter().GetResult();
                if (resp.IsSuccessStatusCode)
                    Terminal.Ok("Webhook test sent! Check your IFTTT activity log.");
                else
                    Terminal.Warn($"Webhook returned {resp.StatusCode}. Check your key.");
            }
            catch (Exception ex)
            {
                Terminal.Warn($"Test failed: {ex.Message}");
            }

            // Start IFTTT poller if not running
            new Thread(IftttPoller) { IsBackground = true, Name = "IFTTT" }.Start();

            Thread.Sleep(2000);
        }

        // ── Server detection ──────────────────────────────────────────────────
        private void AutoDetectServer()
        {
            Console.Clear();
            PrintLogo();
            Console.WriteLine();
            Terminal.Info("Auto-detecting game server...");

            _deviceIp ??= GetConnectedDevice();
            if (_deviceIp == null)
            {
                Terminal.Warn("No device connected. Sampling for 5s...");
                Thread.Sleep(5000);
                _deviceIp = GetConnectedDevice();
                if (_deviceIp == null)
                {
                    Terminal.Error("No device found. Use [2] to enter IP manually.");
                    Thread.Sleep(2000);
                    return;
                }
            }

            Terminal.Info($"Sampling traffic from {_deviceIp} for 5 seconds...");
            Thread.Sleep(5000);

            if (!_devices.TryGetValue(_deviceIp, out var rec))
            {
                Terminal.Warn("No traffic yet. Make sure your console is in-game.");
                Thread.Sleep(2000);
                return;
            }

            var remotes = rec.GetRemotesSorted();
            var gameServer = remotes.FirstOrDefault(r =>
            {
                if (!IsPublicIp(r.Ip)) return false;
                bool hasGamePort = r.Entry.Ports.Any(p =>
                    p != 443 && p != 80 && p != 53 && p != 67 && p != 5353 && p != 1900);
                return hasGamePort && r.Entry.Pkts > 50;
            });

            if (gameServer != null)
            {
                lock (_flowLock) { DisableCutoff(); }
                _serverIp = gameServer.Ip;
                var ports = string.Join(", ", gameServer.Entry.Ports.Where(p => p != 443 && p != 80));
                Terminal.Ok($"Game server detected: {_serverIp}");
                Terminal.Ok($"Ports: {ports}   Packets: {gameServer.Entry.Pkts}");
                Thread.Sleep(1500);
            }
            else
            {
                Terminal.Warn("Could not identify game server. Falling back to manual...");
                Thread.Sleep(1000);
                ManualPickServer();
            }
        }

        private void ManualPickServer()
        {
            Console.Clear();
            PrintLogo();
            Console.WriteLine();

            _deviceIp ??= GetConnectedDevice();
            if (_deviceIp == null) { Terminal.Warn("No device connected."); Thread.Sleep(2000); return; }

            if (!_devices.TryGetValue(_deviceIp, out var rec) || rec.RemoteCount == 0)
            {
                Terminal.Warn("No traffic yet. Make sure your console is in-game.");
                Thread.Sleep(2500);
                return;
            }

            var remotes = rec.GetRemotesSorted()
                .Where(r => IsPublicIp(r.Ip))
                .Take(20)
                .ToList();

            if (remotes.Count == 0) { Terminal.Warn("No public IPs seen yet."); Thread.Sleep(2000); return; }

            Terminal.Header($"Servers seen from {_deviceIp}:");
            Console.WriteLine($"\n  {"#",-4} {"Server IP",-18} {"Pkts",-8} {"Ports"}");
            Console.WriteLine($"  {"─",-4} {"─",-18} {"─",-8} {"─",-20}");
            for (int i = 0; i < remotes.Count; i++)
            {
                var r     = remotes[i];
                var ports = string.Join(", ", r.Entry.Ports.Take(4));
                Console.WriteLine($"  {i + 1,-4} {r.Ip,-18} {r.Entry.Pkts,-8} {ports}");
            }
            Console.WriteLine();
            Console.Write("  Select # (or Enter to cancel): ");
            var line = Console.ReadLine()?.Trim() ?? "";
            if (int.TryParse(line, out var idx) && idx >= 1 && idx <= remotes.Count)
            {
                lock (_flowLock) { DisableCutoff(); }
                _serverIp = remotes[idx - 1].Ip;
                Terminal.Ok($"Server set to {_serverIp}");
                Thread.Sleep(1000);
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────
        private bool IsPublicIp(string ip)
        {
            if (ip == _hotspot.HotspotGateway) return false;
            if (ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172.")) return false;
            if (ip.StartsWith("224.") || ip.StartsWith("239.") || ip.StartsWith("255.")) return false;
            return true;
        }

        private static void PrintLogo()
        {
            Console.WriteLine("\x1b[96m");
            Console.WriteLine(@"    ██████╗██████╗  █████╗ ███████╗██╗  ██╗");
            Console.WriteLine(@"   ██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║");
            Console.WriteLine(@"   ██║     ██████╔╝███████║███████╗███████║");
            Console.WriteLine(@"   ██║     ██╔══██╗██╔══██║╚════██║██╔══██║");
            Console.WriteLine(@"   ╚██████╗██║  ██║██║  ██║███████║██║  ██║");
            Console.WriteLine(@"    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝");
            Console.WriteLine();
            Console.WriteLine(@"    ███████╗██╗    ██╗██╗████████╗ ██████╗██╗  ██╗");
            Console.WriteLine(@"    ██╔════╝██║    ██║██║╚══██╔══╝██╔════╝██║  ██║");
            Console.WriteLine(@"    ███████╗██║ █╗ ██║██║   ██║   ██║     ███████║");
            Console.WriteLine(@"    ╚════██║██║███╗██║██║   ██║   ██║     ██╔══██║");
            Console.WriteLine(@"    ███████║╚███╔███╔╝██║   ██║   ╚██████╗██║  ██║");
            Console.WriteLine(@"    ╚══════╝ ╚══╝╚══╝ ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝");
            Console.WriteLine("\x1b[0m");
        }

        private static void EnableAnsi()
        {
            try
            {
                var handle = GetStdHandle(-11);
                GetConsoleMode(handle, out uint mode);
                SetConsoleMode(handle, mode | 0x0004);
            }
            catch { }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out uint m);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, uint m);

        private static bool IsAdmin()
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public void Dispose()
        {
            if (!_running) return;
            _running = false;
            lock (_flowLock) { DisableCutoff(); }
            _sniffer?.Dispose();
            _hotspot.Stop();
        }
    }
}
