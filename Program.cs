using System;
using System.Security.Principal;
using CrashSwitch;

// Auto-elevate via UAC
using var identity  = WindowsIdentity.GetCurrent();
var       principal = new WindowsPrincipal(identity);
if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
{
    var psi = new System.Diagnostics.ProcessStartInfo(
        System.Diagnostics.Process.GetCurrentProcess().MainModule!.FileName)
    {
        UseShellExecute = true,
        Verb            = "runas",
        Arguments       = string.Join(" ", args),
    };
    try { System.Diagnostics.Process.Start(psi); }
    catch { }
    return;
}

// Enable ANSI
try
{
    var h = GetStdHandle(-11);
    GetConsoleMode(h, out uint m);
    SetConsoleMode(h, m | 0x0004);
}
catch { }

// Extract WinDivert + install Npcap if needed
FirstRunSetup.Run();

// ── License verification ───────────────────────────────────────────────────
// App will not run unless a valid signed token is obtained from the server.
using var auth = new AuthService();
var session = auth.Authenticate();
if (session == null)
{
    Console.WriteLine("\n  License verification failed. Press any key to exit.");
    Console.ReadKey(true);
    return;
}

// ── Launch app with authenticated session ─────────────────────────────────
using var sim = new Simulator(session);
sim.Run();

[System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out uint m);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, uint m);
