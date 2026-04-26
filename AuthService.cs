using System;
using System.IO;
using System.Management;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CrashSwitch
{
    /// <summary>
    /// Holds the verified session. The rest of the app requires this to exist.
    /// If this is null, the app does not run.
    /// </summary>
    public sealed class AuthContext
    {
        public string LicenseKey { get; }
        public string Hwid       { get; }
        public DateTime ExpiresAt { get; }

        public AuthContext(string key, string hwid, DateTime expiresAt)
        {
            LicenseKey = key;
            Hwid       = hwid;
            ExpiresAt  = expiresAt;
        }
    }

    public sealed class AuthService : IDisposable
    {
        // Server URL — change to your Railway URL after deploying
        private const string ServerUrl    = "https://crashswitch-server.up.railway.app";
        private const string JwtIssuer    = "crashswitch-server";
        private const string JwtAudience  = "crashswitch-client";

        // Revalidate 5 minutes before token expires
        private const int RevalidateBeforeSec = 5 * 60;

        private static readonly string KeyFilePath =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "CrashSwitch", "license.key");

        private readonly HttpClient _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10),
        };

        private AuthContext? _context;
        private string?      _currentToken;
        private Timer?       _revalidateTimer;

        // ── Public entry point ────────────────────────────────────────────────
        /// <summary>
        /// Runs the full auth flow. Returns AuthContext on success, null on failure.
        /// </summary>
        public AuthContext? Authenticate()
        {
            EnableAnsi();
            Console.Clear();
            PrintAuthLogo();

            var hwid = GetHwid();
            var key  = GetOrPromptKey();

            if (string.IsNullOrEmpty(key))
            {
                Terminal.Error("No license key provided.");
                Thread.Sleep(2000);
                return null;
            }

            Terminal.Info("Verifying license...");
            var token = VerifyWithServer(key, hwid);

            if (token == null)
            {
                // Error already printed by VerifyWithServer
                Thread.Sleep(3000);
                return null;
            }

            var ctx = BuildContext(token, key, hwid);
            if (ctx == null)
            {
                Terminal.Error("Token validation failed.");
                Thread.Sleep(2000);
                return null;
            }

            SaveKey(key);
            _context      = ctx;
            _currentToken = token;

            Terminal.Ok($"License verified. Valid until {ctx.ExpiresAt:yyyy-MM-dd HH:mm} UTC");
            Thread.Sleep(1200);

            // Schedule silent re-validation
            ScheduleRevalidation(key, hwid, ctx.ExpiresAt);

            return ctx;
        }

        // ── Key storage ───────────────────────────────────────────────────────
        private static string? GetOrPromptKey()
        {
            // Try saved key first
            if (File.Exists(KeyFilePath))
            {
                try
                {
                    var saved = File.ReadAllText(KeyFilePath).Trim();
                    if (!string.IsNullOrEmpty(saved))
                    {
                        Terminal.Info($"Using saved key: {MaskKey(saved)}");
                        return saved;
                    }
                }
                catch { }
            }

            // Prompt
            Console.WriteLine();
            Console.Write("  Enter your license key (format CRASH-XXXX-XXXX-XXXX-XXXX): ");
            var input = Console.ReadLine()?.Trim() ?? "";
            return string.IsNullOrEmpty(input) ? null : input;
        }

        private static void SaveKey(string key)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(KeyFilePath)!);
                File.WriteAllText(KeyFilePath, key);
            }
            catch { }
        }

        private static string MaskKey(string key)
        {
            // Show CRASH-XXXX-????-????-???? 
            var parts = key.Split('-');
            if (parts.Length >= 2)
                return $"{parts[0]}-{parts[1]}-????-????-????";
            return "????";
        }

        // ── HWID generation ───────────────────────────────────────────────────
        /// <summary>
        /// Generates a stable hardware ID from CPU ID + motherboard serial.
        /// Hashed with SHA256 so raw hardware info never leaves the machine.
        /// </summary>
        public static string GetHwid()
        {
            try
            {
                var sb = new StringBuilder();

                // CPU ID
                using var cpu = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor");
                foreach (ManagementObject obj in cpu.Get())
                    sb.Append(obj["ProcessorId"]?.ToString() ?? "");

                // Motherboard serial
                using var mb = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
                foreach (ManagementObject obj in mb.Get())
                    sb.Append(obj["SerialNumber"]?.ToString() ?? "");

                if (sb.Length == 0) sb.Append(Environment.MachineName);

                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            catch
            {
                // Fallback: machine name hash
                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(Environment.MachineName));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        // ── Server verification ───────────────────────────────────────────────
        private string? VerifyWithServer(string key, string hwid)
        {
            try
            {
                var payload = JsonSerializer.Serialize(new { key, hwid });
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                var resp    = _http.PostAsync($"{ServerUrl}/auth/verify", content).GetAwaiter().GetResult();
                var body    = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var doc     = JsonDocument.Parse(body);

                if (!resp.IsSuccessStatusCode)
                {
                    var errMsg = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "Unknown error";
                    Terminal.Error($"License rejected: {errMsg}");
                    return null;
                }

                if (!doc.RootElement.TryGetProperty("token", out var tokenEl))
                {
                    Terminal.Error("Invalid server response.");
                    return null;
                }

                return tokenEl.GetString();
            }
            catch (HttpRequestException)
            {
                Terminal.Error("Could not reach license server. Check your internet connection.");
                return null;
            }
            catch (TaskCanceledException)
            {
                Terminal.Error("License server timed out.");
                return null;
            }
            catch (Exception ex)
            {
                Terminal.Error($"Auth error: {ex.Message}");
                return null;
            }
        }

        // ── JWT validation (client-side, using embedded public key) ───────────
        private static AuthContext? BuildContext(string token, string key, string hwid)
        {
            try
            {
                var publicKeyPem = GetEmbeddedPublicKey();
                if (string.IsNullOrEmpty(publicKeyPem))
                {
                    Terminal.Error("Public key not found in application.");
                    return null;
                }

                // Parse the JWT manually — no external JWT library needed
                // Format: header.payload.signature (all base64url)
                var parts = token.Split('.');
                if (parts.Length != 3)
                {
                    Terminal.Error("Malformed token.");
                    return null;
                }

                // Verify signature with RSA public key
                var headerPayload = $"{parts[0]}.{parts[1]}";
                var signature     = Base64UrlDecode(parts[2]);
                var dataBytes     = Encoding.UTF8.GetBytes(headerPayload);

                using var rsa = RSA.Create();
                rsa.ImportFromPem(publicKeyPem);

                bool valid = rsa.VerifyData(dataBytes, signature,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                if (!valid)
                {
                    Terminal.Error("Token signature invalid — possible tampering detected.");
                    return null;
                }

                // Decode payload
                var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
                var payload     = JsonDocument.Parse(payloadJson).RootElement;

                // Validate issuer
                if (!payload.TryGetProperty("iss", out var iss) || iss.GetString() != JwtIssuer)
                {
                    Terminal.Error("Token issuer invalid.");
                    return null;
                }

                // Validate audience
                if (!payload.TryGetProperty("aud", out var aud) || aud.GetString() != JwtAudience)
                {
                    Terminal.Error("Token audience invalid.");
                    return null;
                }

                // Validate expiry
                if (!payload.TryGetProperty("exp", out var exp))
                {
                    Terminal.Error("Token has no expiry.");
                    return null;
                }
                var expiresAt = DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64()).UtcDateTime;
                if (expiresAt < DateTime.UtcNow)
                {
                    Terminal.Error("Token has expired.");
                    return null;
                }

                // Validate HWID in token matches ours
                if (!payload.TryGetProperty("hwid", out var tokenHwid) || tokenHwid.GetString() != hwid)
                {
                    Terminal.Error("Token HWID mismatch.");
                    return null;
                }

                return new AuthContext(key, hwid, expiresAt);
            }
            catch (Exception ex)
            {
                Terminal.Error($"Token validation error: {ex.Message}");
                return null;
            }
        }

        // ── Embedded public key ───────────────────────────────────────────────
        private static string? GetEmbeddedPublicKey()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                using var stream = asm.GetManifestResourceStream("CrashSwitch.public.pem");
                if (stream == null) return null;
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }
            catch { return null; }
        }

        // ── Silent re-validation ──────────────────────────────────────────────
        private void ScheduleRevalidation(string key, string hwid, DateTime expiresAt)
        {
            var revalidateIn = expiresAt - DateTime.UtcNow - TimeSpan.FromSeconds(RevalidateBeforeSec);
            if (revalidateIn < TimeSpan.FromSeconds(10))
                revalidateIn = TimeSpan.FromSeconds(10);

            _revalidateTimer = new Timer(_ =>
            {
                var newToken = VerifyWithServer(key, hwid);
                if (newToken == null)
                {
                    Terminal.Error("License re-validation failed. Please restart.");
                    return;
                }
                var newCtx = BuildContext(newToken, key, hwid);
                if (newCtx == null) return;
                _context      = newCtx;
                _currentToken = newToken;
                ScheduleRevalidation(key, hwid, newCtx.ExpiresAt);
            }, null, revalidateIn, Timeout.InfiniteTimeSpan);
        }

        // ── Helpers ───────────────────────────────────────────────────────────
        private static byte[] Base64UrlDecode(string input)
        {
            var padded = input.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "=";  break;
            }
            return Convert.FromBase64String(padded);
        }

        private static void PrintAuthLogo()
        {
            Console.WriteLine("\x1b[96m");
            Console.WriteLine(@"    ██████╗██████╗  █████╗ ███████╗██╗  ██╗");
            Console.WriteLine(@"   ██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║");
            Console.WriteLine(@"   ██║     ██████╔╝███████║███████╗███████║");
            Console.WriteLine(@"   ██║     ██╔══██╗██╔══██║╚════██║██╔══██║");
            Console.WriteLine(@"   ╚██████╗██║  ██║██║  ██║███████║██║  ██║");
            Console.WriteLine(@"    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝");
            Console.WriteLine("\x1b[0m");
            Console.WriteLine("  \x1b[2mLicense Verification\x1b[0m");
            Console.WriteLine();
        }

        private static void EnableAnsi()
        {
            try
            {
                var h = GetStdHandle(-11);
                GetConsoleMode(h, out uint m);
                SetConsoleMode(h, m | 0x0004);
            }
            catch { }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out uint m);
        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, uint m);

        public void Dispose()
        {
            _revalidateTimer?.Dispose();
            _http.Dispose();
        }
    }
}
