#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Forensic Artifact Collector v2
.DESCRIPTION
    Collects forensic artifacts: EventLogs, Prefetch, Registry, JumpLists,
    AmCache, LNK, MFT (via RawCopy64), Browser History, Startup items,
    WMI subscriptions, Processes, Network connections, Services, Tasks.
.NOTES
    Run from an elevated PowerShell prompt.
    RawCopy64.exe must be in $toolsPath for MFT collection.
    Get it from: https://github.com/jschicht/RawCopy
#>

$ErrorActionPreference = "Continue"
$timestamp       = Get-Date -Format "yyyyMMdd_HHmmss"
$outputBase      = "C:\ForensicServer"
$toolsPath       = "C:\ForensicServer\Tools"
$collectionName  = "WindowsCollection_$timestamp"
$collectionPath  = "$outputBase\$collectionName"
$TOTAL_STEPS     = 12

# ==================================================================
# HELPER FUNCTIONS
# ==================================================================

function Write-Status ($msg, $color = "Green") {
    Write-Host "  [+] $msg" -ForegroundColor $color
}

function Write-Warn ($msg) {
    Write-Host "  [!] $msg" -ForegroundColor Yellow
}

function Write-Fail ($msg) {
    Write-Host "  [-] $msg" -ForegroundColor Red
}

function Write-Step ($n, $total, $msg) {
    Write-Host ""
    Write-Host "[$n/$total] $msg" -ForegroundColor Cyan
}

function Get-RawCopyExe {
    foreach ($name in @("RawCopy64.exe", "RawCopy.exe")) {
        $p = "$toolsPath\$name"
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Copy-LockedFile ($src, $dst) {
    # Attempt 1: direct copy
    try {
        Copy-Item -Path $src -Destination $dst -Force -ErrorAction Stop
        return $true
    } catch {}

    # Attempt 2: RawCopy (raw NTFS, bypasses file locks)
    $rawCopy = Get-RawCopyExe
    if ($rawCopy) {
        Start-Process -FilePath $rawCopy `
            -ArgumentList "/FileNamePath:$src", "/OutputPath:$(Split-Path $dst)" `
            -NoNewWindow -Wait 2>&1 | Out-Null
        if (Test-Path $dst) { return $true }
    }

    return $false
}

function New-VolumeShadowCopy {
    # Method A: vssadmin (most reliable -- output includes the full device path)
    try {
        $out = & vssadmin create shadow /for=C: 2>&1
        # Parse the line containing the shadow volume path (works EN + FR Windows)
        foreach ($line in $out) {
            if ($line -match "GLOBALROOT|HarddiskVolumeShadowCopy") {
                # Extract everything after the last colon+space
                $devName = ($line -split ":\s+",2)[-1].Trim()
                if ($devName -match "HarddiskVolumeShadowCopy") {
                    # Normalise to \?\GLOBALROOT\... form
                    if ($devName -notmatch "^\\\\") { $devName = "\\?\$devName" }
                    Write-Host "  [*] VSS device: $devName" -ForegroundColor DarkGray
                    return [PSCustomObject]@{ DeviceName = $devName; _vssadmin = $true }
                }
            }
        }
    } catch {}

    # Method B: WMI Create (fallback)
    try {
        $before = @(Get-WmiObject Win32_ShadowCopy | Select-Object -ExpandProperty ID)
        (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible") | Out-Null
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Milliseconds 500
            $new = @(Get-WmiObject Win32_ShadowCopy) |
                Where-Object { ($before -notcontains $_.ID) -and ($_.DeviceName -ne "") }
            if ($new) {
                $s = $new | Sort-Object InstallDate -Descending | Select-Object -First 1
                Write-Host "  [*] VSS device: $($s.DeviceName)" -ForegroundColor DarkGray
                return $s
            }
        }
    } catch {}

    return $null
}

function Copy-FileViaVSS ($shadowDevice, $srcRelative, $dst) {
    # shadowDevice: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
    # srcRelative:  \Users\zaidi\NTUSER.DAT  (must start with backslash)
    if (-not $srcRelative.StartsWith("\")) { $srcRelative = "\$srcRelative" }

    # Method 1: mklink symlink then normal Copy-Item (most compatible)
    $tempLink = "$env:TEMP\vsslnk_$([System.IO.Path]::GetRandomFileName() -replace '\..*')"
    try {
        # mklink /d linkname target -- target must NOT have trailing backslash
        $target = $shadowDevice.TrimEnd("\")
        cmd /c "mklink /d `"$tempLink`" `"$target`"" 2>&1 | Out-Null
        if (Test-Path "$tempLink\") {
            Copy-Item "$tempLink$srcRelative" $dst -Force -ErrorAction Stop
            Remove-Item $tempLink -Force -ErrorAction SilentlyContinue
            return (Test-Path $dst)
        }
    } catch {}
    Remove-Item $tempLink -Force -ErrorAction SilentlyContinue

    # Method 2: direct path  \\?\GLOBALROOT\...\Users\zaidi\NTUSER.DAT
    try {
        $fullPath = $shadowDevice.TrimEnd("\") + $srcRelative
        Copy-Item $fullPath $dst -Force -ErrorAction Stop
        return (Test-Path $dst)
    } catch {}

    return $false
}

function Remove-VolumeShadowCopy ($shadow) {
    if (-not $shadow) { return }
    try {
        if ($shadow.PSObject.Properties.Name -contains "_vssadmin") {
            # Created via vssadmin -- delete via vssadmin
            & vssadmin delete shadows /shadow=$($shadow.DeviceName) /quiet 2>&1 | Out-Null
        } else {
            $shadow.Delete() | Out-Null
        }
    } catch {}
}

# ==================================================================
# BANNER
# ==================================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  WINDOWS FORENSIC COLLECTOR v2" -ForegroundColor Cyan
Write-Host "  Host : $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  User : $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
Write-Host "  ID   : $timestamp" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# ==================================================================
# [1] CREATE DIRECTORY STRUCTURE
# ==================================================================

Write-Step 1 $TOTAL_STEPS "Creating collection directories"

$dirs = @(
    "EventLogs\Security", "EventLogs\System", "EventLogs\Application",
    "EventLogs\Sysmon",   "EventLogs\PowerShell",
    "Prefetch", "Registry", "JumpLists", "AmCache",
    "LNK",      "MFT",
    "BrowserHistory\Chrome", "BrowserHistory\Edge", "BrowserHistory\Firefox",
    "Startup",  "WMI",
    "ProcessList", "NetworkConnections", "ScheduledTasks", "Services"
)

foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force -Path "$collectionPath\$d" | Out-Null
}

Write-Status "Created: $collectionPath"

# ==================================================================
# [2] EVENT LOGS
# ==================================================================

Write-Step 2 $TOTAL_STEPS "Collecting Event Logs"

$sysmonFound   = $false
$evtxCollected = 0

$eventLogs = [ordered]@{
    "Security"                                                               = "EventLogs\Security\Security.evtx"
    "System"                                                                 = "EventLogs\System\System.evtx"
    "Application"                                                            = "EventLogs\Application\Application.evtx"
    "Microsoft-Windows-Sysmon/Operational"                                   = "EventLogs\Sysmon\Sysmon.evtx"
    "Microsoft-Windows-PowerShell/Operational"                               = "EventLogs\PowerShell\PowerShell_Operational.evtx"
    "Windows PowerShell"                                                     = "EventLogs\PowerShell\PowerShell_Classic.evtx"
    "Microsoft-Windows-TaskScheduler/Operational"                            = "EventLogs\System\TaskScheduler.evtx"
    "Microsoft-Windows-WMI-Activity/Operational"                             = "EventLogs\System\WMI_Activity.evtx"
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"     = "EventLogs\System\RDP_LocalSession.evtx"
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" = "EventLogs\System\RDP_RemoteConn.evtx"
    "Microsoft-Windows-Bits-Client/Operational"                              = "EventLogs\System\BitsClient.evtx"
    "Microsoft-Windows-DNS-Client/Operational"                               = "EventLogs\System\DNS_Client.evtx"
    "Microsoft-Windows-Windows Defender/Operational"                         = "EventLogs\System\Defender.evtx"
}

foreach ($log in $eventLogs.Keys) {
    try {
        $outFile = "$collectionPath\$($eventLogs[$log])"
        wevtutil epl "$log" "$outFile" 2>&1 | Out-Null
        if (Test-Path $outFile) {
            $sizeMB = [math]::Round((Get-Item $outFile).Length / 1MB, 2)
            if ($log -like "*Sysmon*") {
                Write-Status "$(Split-Path $outFile -Leaf) (${sizeMB} MB) [SYSMON]" "Magenta"
                $sysmonFound = $true
            } else {
                Write-Status "$(Split-Path $outFile -Leaf) (${sizeMB} MB)"
            }
            $evtxCollected++
        }
    } catch {
        Write-Warn "$log -- not available"
    }
}

if (-not $sysmonFound) {
    Write-Warn "Sysmon NOT installed -- process/network/file events will be absent"
}
Write-Status "Total: $evtxCollected event logs"

# ==================================================================
# [3] PREFETCH
# ==================================================================

Write-Step 3 $TOTAL_STEPS "Collecting Prefetch files"

$pfCount = 0
$pfPath  = "C:\Windows\Prefetch"

if (Test-Path $pfPath) {
    Get-ChildItem "$pfPath\*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item $_.FullName "$collectionPath\Prefetch\" -Force -ErrorAction SilentlyContinue
        $pfCount++
    }
    if (Test-Path "$pfPath\Layout.ini") {
        Copy-Item "$pfPath\Layout.ini" "$collectionPath\Prefetch\" -Force -ErrorAction SilentlyContinue
    }
    Write-Status "$pfCount prefetch files collected"
} else {
    Write-Warn "Prefetch directory not found (may be disabled)"
}

# ==================================================================
# [4] REGISTRY HIVES
# ==================================================================

Write-Step 4 $TOTAL_STEPS "Collecting Registry hives"

$regCollected = 0

$systemHives = [ordered]@{
    "HKLM\SYSTEM"   = "Registry\SYSTEM.hiv"
    "HKLM\SOFTWARE" = "Registry\SOFTWARE.hiv"
    "HKLM\SAM"      = "Registry\SAM.hiv"
    "HKLM\SECURITY" = "Registry\SECURITY.hiv"
}

foreach ($hive in $systemHives.Keys) {
    $out = "$collectionPath\$($systemHives[$hive])"
    reg save $hive $out /y 2>&1 | Out-Null
    if (Test-Path $out) {
        $sizeMB = [math]::Round((Get-Item $out).Length / 1MB, 2)
        Write-Status "$(Split-Path $out -Leaf) (${sizeMB} MB)"
        $regCollected++
    } else {
        Write-Fail "$(Split-Path $out -Leaf) -- failed"
    }
}

# Create one VSS snapshot for all locked per-user hives
Write-Host "  [*] Creating VSS snapshot for locked hives..." -ForegroundColor DarkGray
$shadow = New-VolumeShadowCopy
if ($shadow) {
    Write-Status "VSS snapshot created: $($shadow.DeviceName)"
} else {
    Write-Warn "VSS snapshot failed -- will try reg save fallback for each user"
}

Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "^(Public|Default|All Users|Default User)$" } |
    ForEach-Object {
        $userName = $_.Name
        $userPath = $_.FullName

        # NTUSER.DAT -- try reg save first, then VSS, then direct copy
        $out = "$collectionPath\Registry\NTUSER_${userName}.DAT"
        $got = $false

        # Method 1: reg save (works for currently loaded hives)
        reg save "HKU\$userName" $out /y 2>&1 | Out-Null
        if (Test-Path $out) { $got = $true }

        # Method 2: VSS copy (works for locked files)
        if (-not $got -and $shadow) {
            $rel = $userPath -replace "^[A-Za-z]:", ""
            $got = Copy-FileViaVSS $shadow.DeviceName "$rel\NTUSER.DAT" $out
        }

        # Method 3: direct copy last resort (suppress error -- file is usually locked)
        if (-not $got) {
            try {
                Copy-Item "$userPath\NTUSER.DAT" $out -Force -ErrorAction Stop
                if (Test-Path $out) { $got = $true }
            } catch {}
        }

        if ($got) {
            Write-Status "NTUSER_${userName}.DAT"
            $regCollected++
        } else {
            Write-Warn "NTUSER_${userName}.DAT -- all methods failed"
        }

        # UsrClass.dat (shellbags)
        $usrClassRel = "\AppData\Local\Microsoft\Windows\UsrClass.dat"
        $usrClassSrc = "$userPath$usrClassRel"
        $outUsr      = "$collectionPath\Registry\UsrClass_${userName}.dat"
        $gotUsr      = $false

        if ($shadow) {
            $rel = $userPath -replace "^[A-Za-z]:", ""
            $gotUsr = Copy-FileViaVSS $shadow.DeviceName "$rel$usrClassRel" $outUsr
        }
        if (-not $gotUsr -and (Test-Path $usrClassSrc)) {
            try {
                Copy-Item $usrClassSrc $outUsr -Force -ErrorAction Stop
                if (Test-Path $outUsr) { $gotUsr = $true }
            } catch {}
        }

        if ($gotUsr) {
            Write-Status "UsrClass_${userName}.dat (shellbags)"
            $regCollected++
        }
    }

# Delete the VSS snapshot we created (clean up)
if ($shadow) {
    try {
        Remove-VolumeShadowCopy $shadow
        Write-Host "  [*] VSS snapshot removed" -ForegroundColor DarkGray
    } catch {}
}

Write-Status "Total: $regCollected registry hives"

# ==================================================================
# [5] JUMPLISTS + LNK
# ==================================================================

Write-Step 5 $TOTAL_STEPS "Collecting JumpLists and LNK files"

$jlCount  = 0
$lnkCount = 0

Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "^(Public|Default|All Users)$" } |
    ForEach-Object {
        $userName = $_.Name
        $userPath = $_.FullName

        foreach ($sub in @("AutomaticDestinations", "CustomDestinations")) {
            $src = "$userPath\AppData\Roaming\Microsoft\Windows\Recent\$sub"
            if (Test-Path $src) {
                Get-ChildItem $src -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Copy-Item $_.FullName "$collectionPath\JumpLists\" -Force -ErrorAction SilentlyContinue
                    $jlCount++
                }
            }
        }

        foreach ($lnkSrc in @(
            "$userPath\AppData\Roaming\Microsoft\Windows\Recent",
            "$userPath\Desktop",
            "$userPath\AppData\Roaming\Microsoft\Windows\SendTo"
        )) {
            if (Test-Path $lnkSrc) {
                Get-ChildItem "$lnkSrc\*.lnk" -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $dest = "$collectionPath\LNK\${userName}_$($_.Name)"
                    Copy-Item $_.FullName $dest -Force -ErrorAction SilentlyContinue
                    $lnkCount++
                }
            }
        }
    }

if ($jlCount  -gt 0) { Write-Status "$jlCount jump list files"  } else { Write-Warn "No jump lists found" }
if ($lnkCount -gt 0) { Write-Status "$lnkCount LNK files"       } else { Write-Warn "No LNK files found"  }

# ==================================================================
# [6] AMCACHE
# ==================================================================

Write-Step 6 $TOTAL_STEPS "Collecting AmCache"

$amcacheCollected = $false
$amcacheSrc       = "C:\Windows\AppCompat\Programs\Amcache.hve"

if (Test-Path $amcacheSrc) {
    $amcacheDst = "$collectionPath\AmCache\Amcache.hve"
    $ok = $false

    # Try 1: direct copy (works if AppIDSvc is stopped)
    try {
        Copy-Item $amcacheSrc $amcacheDst -Force -ErrorAction Stop
        $ok = $true
    } catch {}

    # Try 2: stop AppIDSvc, copy, restart
    if (-not $ok) {
        try {
            $svc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Stop-Service -Name "AppIDSvc" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Copy-Item $amcacheSrc $amcacheDst -Force -ErrorAction Stop
                Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
                $ok = $true
            }
        } catch {
            Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        }
    }

    # Try 3: RawCopy
    if (-not $ok) {
        $rawCopy = Get-RawCopyExe
        if ($rawCopy) {
            Start-Process -FilePath $rawCopy `
                -ArgumentList "/FileNamePath:$amcacheSrc", "/OutputPath:$collectionPath\AmCache" `
                -NoNewWindow -Wait
            if (Test-Path $amcacheDst) { $ok = $true }
        }
    }

    # Try 4: VSS (most reliable when all else fails)
    if (-not $ok) {
        Write-Host "  [*] Trying VSS for Amcache.hve..." -ForegroundColor DarkGray
        $amShadow = New-VolumeShadowCopy
        if ($amShadow) {
            $rel = $amcacheSrc -replace "^[A-Za-z]:", ""
            $ok = Copy-FileViaVSS $amShadow.DeviceName $rel $amcacheDst
            Remove-VolumeShadowCopy $amShadow
        }
    }

    if ($ok) {
        Write-Status "Amcache.hve"
        $amcacheCollected = $true
    } else {
        Write-Fail "Amcache.hve -- all methods failed (file locked)"
    }
} else {
    Write-Warn "Amcache.hve not found"
}

# ==================================================================
# [7] MFT (Master File Table)
# ==================================================================

Write-Step 7 $TOTAL_STEPS "Collecting MFT (Master File Table)"

$mftCollected = $false
$rawCopy      = Get-RawCopyExe

if ($rawCopy) {
    try {
        $mftDst  = "$collectionPath\MFT"
        # Both RawCopy.exe and RawCopy64.exe accept C:\$MFT (drive-letter path)
        $mftPath = "C:\`$MFT"
        $mftArgs = @("/FileNamePath:$mftPath", "/OutputPath:$mftDst")

        Start-Process -FilePath $rawCopy -ArgumentList $mftArgs `
            -NoNewWindow -Wait `
            -RedirectStandardOutput "$mftDst\rawcopy_stdout.txt" `
            -RedirectStandardError  "$mftDst\rawcopy_stderr.txt"

        # Find the output file (some versions name it $MFT, some use the volume name)
        $mftOut = Get-ChildItem $mftDst -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch "rawcopy" } |
            Sort-Object Length -Descending | Select-Object -First 1

        if ($mftOut -and $mftOut.Length -gt 1MB) {
            if ($mftOut.Name -ne "`$MFT") {
                Rename-Item $mftOut.FullName "$mftDst\`$MFT" -ErrorAction SilentlyContinue
            }
            $sizeMB = [math]::Round($mftOut.Length / 1MB, 0)
            Write-Status "`$MFT collected (~${sizeMB} MB) via $(Split-Path $rawCopy -Leaf)"
            $mftCollected = $true
        } else {
            $errText = ""
            $outText = ""
            if (Test-Path "$mftDst\rawcopy_stderr.txt") {
                $errText = (Get-Content "$mftDst\rawcopy_stderr.txt" -Raw -ErrorAction SilentlyContinue).Trim()
            }
            if (Test-Path "$mftDst\rawcopy_stdout.txt") {
                $outText = (Get-Content "$mftDst\rawcopy_stdout.txt" -Raw -ErrorAction SilentlyContinue).Trim()
            }
            Write-Warn "RawCopy ran but `$MFT not found."
            if ($errText) { Write-Host "      stderr: $errText" -ForegroundColor DarkGray }
            if ($outText) { Write-Host "      stdout: $outText" -ForegroundColor DarkGray }
            Write-Host "      Try manually: $rawCopy /FileNamePath:C:\`$MFT /OutputPath:$mftDst" -ForegroundColor Yellow
        }
    } catch {
        Write-Fail "RawCopy error: $_"
    }
} else {
    Write-Warn "RawCopy(64).exe not found in $toolsPath -- skipping MFT"
    Write-Host "      Get it from: https://github.com/jschicht/RawCopy" -ForegroundColor DarkGray
}

# ==================================================================
# [8] BROWSER HISTORY
# ==================================================================

Write-Step 8 $TOTAL_STEPS "Collecting Browser History"

$browserCount = 0

Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "^(Public|Default|All Users|Default User)$" } |
    ForEach-Object {
        $userName = $_.Name
        $userPath = $_.FullName

        # Chrome
        foreach ($profileName in @("Default", "Profile 1", "Profile 2")) {
            $profile = "$userPath\AppData\Local\Google\Chrome\User Data\$profileName"
            if (Test-Path $profile) {
                $tag = $profileName -replace " ", "_"
                foreach ($file in @("History", "Cookies", "Web Data", "Login Data", "Bookmarks")) {
                    $src = "$profile\$file"
                    if (Test-Path $src) {
                        Copy-Item $src "$collectionPath\BrowserHistory\Chrome\${userName}_${tag}_$file" `
                            -Force -ErrorAction SilentlyContinue
                        $browserCount++
                    }
                }
            }
        }

        # Edge
        foreach ($profileName in @("Default", "Profile 1")) {
            $profile = "$userPath\AppData\Local\Microsoft\Edge\User Data\$profileName"
            if (Test-Path $profile) {
                $tag = $profileName -replace " ", "_"
                foreach ($file in @("History", "Cookies", "Web Data", "Login Data", "Bookmarks")) {
                    $src = "$profile\$file"
                    if (Test-Path $src) {
                        Copy-Item $src "$collectionPath\BrowserHistory\Edge\${userName}_${tag}_$file" `
                            -Force -ErrorAction SilentlyContinue
                        $browserCount++
                    }
                }
            }
        }

        # Firefox
        $ffBase = "$userPath\AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $ffBase) {
            Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $profileTag = $_.Name
                foreach ($file in @("places.sqlite", "cookies.sqlite", "formhistory.sqlite", "logins.json")) {
                    $src = "$($_.FullName)\$file"
                    if (Test-Path $src) {
                        Copy-Item $src "$collectionPath\BrowserHistory\Firefox\${userName}_${profileTag}_$file" `
                            -Force -ErrorAction SilentlyContinue
                        $browserCount++
                    }
                }
            }
        }
    }

if ($browserCount -gt 0) {
    Write-Status "$browserCount browser artifact files"
} else {
    Write-Warn "No browser artifacts found"
}

# ==================================================================
# [9] STARTUP ITEMS
# ==================================================================

Write-Step 9 $TOTAL_STEPS "Collecting Startup Items"

$startupRegKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$startupItems = @()
foreach ($key in $startupRegKeys) {
    try {
        $props = Get-ItemProperty -Path $key -ErrorAction Stop
        $props.PSObject.Properties |
            Where-Object { $_.Name -notmatch "^PS" } |
            ForEach-Object {
                $startupItems += [PSCustomObject]@{
                    Source = $key
                    Name   = $_.Name
                    Value  = $_.Value
                }
            }
    } catch {}
}

$startupItems | Export-Csv "$collectionPath\Startup\startup_registry.csv" -NoTypeInformation -Encoding UTF8
Write-Status "$($startupItems.Count) registry startup entries"

$startupFolders = [System.Collections.ArrayList]@(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "^(Public|Default|All Users|Default User)$" } |
    ForEach-Object {
        [void]$startupFolders.Add(
            "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        )
    }

$sfCount = 0
foreach ($sf in $startupFolders) {
    if (Test-Path $sf) {
        Get-ChildItem $sf -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName "$collectionPath\Startup\" -Force -ErrorAction SilentlyContinue
            $sfCount++
        }
    }
}
Write-Status "$sfCount startup folder files"

# ==================================================================
# [10] WMI SUBSCRIPTIONS
# ==================================================================

Write-Step 10 $TOTAL_STEPS "Collecting WMI Subscriptions"

try {
    $wmiFilters   = @(Get-WMIObject -Namespace "root\subscription" -Class __EventFilter            -ErrorAction Stop)
    $wmiConsumers = @(Get-WMIObject -Namespace "root\subscription" -Class __EventConsumer           -ErrorAction Stop)
    $wmiBindings  = @(Get-WMIObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction Stop)

    $wmiFilters | Select-Object Name, Query, QueryLanguage |
        Export-Csv "$collectionPath\WMI\wmi_event_filters.csv" -NoTypeInformation -Encoding UTF8

    $wmiConsumers | Select-Object Name, CommandLineTemplate, ScriptText, ScriptFileName |
        Export-Csv "$collectionPath\WMI\wmi_consumers.csv" -NoTypeInformation -Encoding UTF8

    $wmiBindings | Select-Object Filter, Consumer |
        Export-Csv "$collectionPath\WMI\wmi_bindings.csv" -NoTypeInformation -Encoding UTF8

    if ($wmiFilters.Count -gt 0 -or $wmiConsumers.Count -gt 0) {
        Write-Warn "$($wmiFilters.Count) WMI filters, $($wmiConsumers.Count) consumers -- review WMI\ folder!"
    } else {
        Write-Status "WMI subscriptions collected (none active)"
    }
} catch {
    Write-Fail "WMI collection failed: $_"
}

# ==================================================================
# [11] VOLATILE DATA: PROCESSES, NETWORK, SERVICES, TASKS
# ==================================================================

Write-Step 11 $TOTAL_STEPS "Collecting Volatile Data"

# Processes with SHA256 hashes
try {
    Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet,
        @{N='Path'; E={ try { $_.MainModule.FileName } catch { '' } }},
        @{N='Hash'; E={
            $p = try { $_.MainModule.FileName } catch { '' }
            if ($p -and (Test-Path $p)) {
                (Get-FileHash $p -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            } else { '' }
        }},
        @{N='Owner'; E={
            try {
                $o = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner()
                "$($o.Domain)\$($o.User)"
            } catch { '' }
        }},
        StartTime |
        Export-Csv "$collectionPath\ProcessList\running_processes.csv" -NoTypeInformation -Encoding UTF8

    $pCount = (Import-Csv "$collectionPath\ProcessList\running_processes.csv").Count
    Write-Status "$pCount processes captured (with SHA256)"
} catch {
    Write-Fail "Process list failed: $_"
}

# TCP connections
try {
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
        @{N='ProcessName'; E={ try { (Get-Process -Id $_.OwningProcess -EA Stop).ProcessName } catch { '' } }} |
        Export-Csv "$collectionPath\NetworkConnections\tcp_connections.csv" -NoTypeInformation -Encoding UTF8
    Write-Status "TCP connections captured"
} catch {
    Write-Fail "TCP connections failed: $_"
}

# UDP endpoints
try {
    Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess,
        @{N='ProcessName'; E={ try { (Get-Process -Id $_.OwningProcess -EA Stop).ProcessName } catch { '' } }} |
        Export-Csv "$collectionPath\NetworkConnections\udp_endpoints.csv" -NoTypeInformation -Encoding UTF8
    Write-Status "UDP endpoints captured"
} catch {
    Write-Fail "UDP endpoints failed: $_"
}

# DNS cache
try {
    Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Data, TimeToLive |
        Export-Csv "$collectionPath\NetworkConnections\dns_cache.csv" -NoTypeInformation -Encoding UTF8
    Write-Status "DNS cache captured"
} catch {
    Write-Warn "DNS cache not available"
}

# Named pipes
try {
    [System.IO.Directory]::GetFiles('\\.\pipe\') |
        ForEach-Object { [PSCustomObject]@{ PipeName = $_ } } |
        Export-Csv "$collectionPath\NetworkConnections\named_pipes.csv" -NoTypeInformation -Encoding UTF8
    Write-Status "Named pipes enumerated"
} catch {
    Write-Warn "Named pipes not available"
}

# Scheduled tasks
try {
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
        @{N='Actions';  E={ ($_.Actions  | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' }},
        @{N='Triggers'; E={ ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ' | ' }},
        @{N='RunAs';    E={ $_.Principal.UserId }} |
        Export-Csv "$collectionPath\ScheduledTasks\scheduled_tasks.csv" -NoTypeInformation -Encoding UTF8
    Write-Status "Scheduled tasks captured"
} catch {
    Write-Fail "Scheduled tasks failed: $_"
}

# Services with binary paths
try {
    Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
        Export-Csv "$collectionPath\Services\services.csv" -NoTypeInformation -Encoding UTF8
    Write-Status "Services captured (with binary paths)"
} catch {
    Write-Fail "Services failed: $_"
}

# ==================================================================
# [12] MANIFEST + COMPRESS
# ==================================================================

Write-Step 12 $TOTAL_STEPS "Creating Manifest and Compressing"

$os = Get-CimInstance Win32_OperatingSystem

$manifest = [ordered]@{
    Schema            = "WindowsCollection/v2"
    CollectionID      = $timestamp
    CollectionName    = $collectionName
    Hostname          = $env:COMPUTERNAME
    Username          = "$env:USERDOMAIN\$env:USERNAME"
    OS                = $os.Caption
    OSVersion         = $os.Version
    OSBuild           = $os.BuildNumber
    Architecture      = $os.OSArchitecture
    CollectionDate    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    CollectionDateUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    SysmonInstalled   = $sysmonFound
    Artifacts         = [ordered]@{
        EventLogs               = $evtxCollected
        PrefetchFiles           = $pfCount
        RegistryHives           = $regCollected
        JumpLists               = $jlCount
        LNKFiles                = $lnkCount
        AmCacheCollected        = $amcacheCollected
        MFTCollected            = $mftCollected
        BrowserFiles            = $browserCount
        WMICollected            = (Test-Path "$collectionPath\WMI\wmi_event_filters.csv")
        ProcessListCollected    = (Test-Path "$collectionPath\ProcessList\running_processes.csv")
        NetworkCollected        = (Test-Path "$collectionPath\NetworkConnections\tcp_connections.csv")
        ScheduledTasksCollected = (Test-Path "$collectionPath\ScheduledTasks\scheduled_tasks.csv")
        ServicesCollected       = (Test-Path "$collectionPath\Services\services.csv")
    }
}

$manifest | ConvertTo-Json -Depth 5 | Out-File "$collectionPath\MANIFEST.json" -Encoding UTF8
Write-Status "MANIFEST.json written"

$zipFile = "$outputBase\${collectionName}.zip"
try {
    Compress-Archive -Path "$collectionPath\*" -DestinationPath $zipFile -Force -CompressionLevel Optimal
    if (Test-Path $zipFile) {
        $sizeMB = [math]::Round((Get-Item $zipFile).Length / 1MB, 2)
        $hash   = (Get-FileHash $zipFile -Algorithm SHA256).Hash
        "$hash  ${collectionName}.zip" | Out-File "$outputBase\${collectionName}.sha256" -Encoding ASCII
        Write-Status "Archive: $zipFile (${sizeMB} MB)"
        Write-Status "SHA256 : $hash"
        Remove-Item -Path $collectionPath -Recurse -Force
        Write-Status "Temp folder cleaned"
    }
} catch {
    Write-Fail "Compression failed: $_"
    Write-Host "      Raw collection preserved at: $collectionPath" -ForegroundColor Yellow
}

# ==================================================================
# SUMMARY
# ==================================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  COLLECTION COMPLETE" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Event Logs    : $evtxCollected"   -ForegroundColor White
Write-Host "  Prefetch      : $pfCount"          -ForegroundColor White
Write-Host "  Registry      : $regCollected"     -ForegroundColor White
Write-Host "  JumpLists     : $jlCount"          -ForegroundColor White
Write-Host "  LNK Files     : $lnkCount"         -ForegroundColor White
Write-Host "  Browser Files : $browserCount"     -ForegroundColor White
Write-Host "  AmCache       : $amcacheCollected" -ForegroundColor White
Write-Host "  MFT           : $mftCollected"     -ForegroundColor White
Write-Host ""
Write-Host "  Archive : $zipFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next: python windows_parser.py $collectionName CASE-XXXX" -ForegroundColor Yellow
Write-Host ""
