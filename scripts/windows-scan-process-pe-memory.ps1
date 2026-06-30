param(
    [Parameter(Mandatory=$true)]
    [int]$TargetPid,

    [string]$OutputPath = "",

    [string]$ExpectedBase = ""
)

$ErrorActionPreference = "Stop"

if (-not ("MemScanNativePe" -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class MemScanNativePe {
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION64 {
        public UInt64 BaseAddress;
        public UInt64 AllocationBase;
        public UInt32 AllocationProtect;
        public UInt16 PartitionId;
        public UInt64 RegionSize;
        public UInt32 State;
        public UInt32 Protect;
        public UInt32 Type;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);
}
"@
}

function Hex64([UInt64]$v) {
    return ("0x{0:x16}" -f $v)
}

function ProtectName([uint32]$p) {
    $base = $p -band 0xff
    $name = switch ($base) {
        0x01 { "PAGE_NOACCESS" }
        0x02 { "PAGE_READONLY" }
        0x04 { "PAGE_READWRITE" }
        0x08 { "PAGE_WRITECOPY" }
        0x10 { "PAGE_EXECUTE" }
        0x20 { "PAGE_EXECUTE_READ" }
        0x40 { "PAGE_EXECUTE_READWRITE" }
        0x80 { "PAGE_EXECUTE_WRITECOPY" }
        default { ("UNKNOWN_0x{0:x}" -f $base) }
    }
    if ($p -band 0x100) { $name += "|PAGE_GUARD" }
    if ($p -band 0x200) { $name += "|PAGE_NOCACHE" }
    if ($p -band 0x400) { $name += "|PAGE_WRITECOMBINE" }
    return $name
}

function TypeName([uint32]$t) {
    switch ($t) {
        0x1000000 { "MEM_IMAGE" }
        0x40000   { "MEM_MAPPED" }
        0x20000   { "MEM_PRIVATE" }
        default   { ("UNKNOWN_0x{0:x}" -f $t) }
    }
}

function StateName([uint32]$s) {
    switch ($s) {
        0x1000  { "MEM_COMMIT" }
        0x2000  { "MEM_RESERVE" }
        0x10000 { "MEM_FREE" }
        default { ("UNKNOWN_0x{0:x}" -f $s) }
    }
}

function IsExecuteProtect([uint32]$p) {
    $base = $p -band 0xff
    return ($base -eq 0x10 -or $base -eq 0x20 -or $base -eq 0x40 -or $base -eq 0x80)
}

function Read-Bytes($Handle, [UInt64]$Address, [UInt64]$Size) {
    if ($Size -le 0) { return ,@() }
    $n = [int][Math]::Min([UInt64]$Size, [UInt64]65536)
    $buf = New-Object byte[] $n
    [UIntPtr]$read = [UIntPtr]::Zero
    $ok = [MemScanNativePe]::ReadProcessMemory($Handle, [UIntPtr]$Address, $buf, [UIntPtr][uint64]$n, [ref]$read)
    if (-not $ok -or $read.ToUInt64() -eq 0) { return $null }
    if ($read.ToUInt64() -lt [uint64]$n) {
        $short = New-Object byte[] ([int]$read.ToUInt64())
        [Array]::Copy($buf, $short, $short.Length)
        return ,$short
    }
    return ,$buf
}

function U16($b, [int]$off) {
    if (-not $b -or $off + 2 -gt $b.Length) { return $null }
    return [BitConverter]::ToUInt16($b, $off)
}

function U32($b, [int]$off) {
    if (-not $b -or $off + 4 -gt $b.Length) { return $null }
    return [BitConverter]::ToUInt32($b, $off)
}

function Analyze-PeHeader($b) {
    $result = [ordered]@{
        mz = $false
        pe_by_lfanew = $false
        e_lfanew = $null
        machine = $null
        number_of_sections = $null
        size_of_optional_header = $null
        optional_magic = $null
        size_of_image = $null
        size_of_headers = $null
        number_of_rva_and_sizes = $null
        data_directory_offset = $null
        data_directories = @()
        section_table_offset = $null
        section_names = @()
        first_16 = $null
    }
    if (-not $b -or $b.Length -lt 0x40) { return $result }
    $result.first_16 = (($b[0..([Math]::Min(15, $b.Length-1))] | ForEach-Object { "{0:x2}" -f $_ }) -join "")
    $result.mz = ($b[0] -eq 0x4d -and $b[1] -eq 0x5a)
    $e = U32 $b 0x3c
    $result.e_lfanew = $e
    if ($null -eq $e -or $e -le 0 -or $e + 0x18 -ge $b.Length) { return $result }
    $result.pe_by_lfanew = ($b[$e] -eq 0x50 -and $b[$e+1] -eq 0x45 -and $b[$e+2] -eq 0 -and $b[$e+3] -eq 0)
    if (-not $result.pe_by_lfanew) { return $result }
    $file = [int]$e + 4
    $result.machine = U16 $b $file
    $result.number_of_sections = U16 $b ($file + 2)
    $result.size_of_optional_header = U16 $b ($file + 16)
    $opt = $file + 20
    $result.optional_magic = U16 $b $opt
    $result.size_of_image = U32 $b ($opt + 0x38)
    $result.size_of_headers = U32 $b ($opt + 0x3c)
    $dirNames = @(
        "EXPORT","IMPORT","RESOURCE","EXCEPTION",
        "SECURITY","BASERELOC","DEBUG","ARCHITECTURE",
        "GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT",
        "IAT","DELAY_IMPORT","COM_DESCRIPTOR","RESERVED"
    )
    $numberOffset = $null
    $dirOffset = $null
    if ($result.optional_magic -eq 0x20b) {
        $numberOffset = $opt + 0x6c
        $dirOffset = $opt + 0x70
    } elseif ($result.optional_magic -eq 0x10b) {
        $numberOffset = $opt + 0x5c
        $dirOffset = $opt + 0x60
    }
    if ($null -ne $dirOffset -and $numberOffset + 4 -le $b.Length) {
        $result.number_of_rva_and_sizes = U32 $b $numberOffset
        $result.data_directory_offset = $dirOffset
        $dirCount = 0
        if ($null -ne $result.number_of_rva_and_sizes) { $dirCount = [int][Math]::Min([uint32]$result.number_of_rva_and_sizes, [uint32]16) }
        for ($i = 0; $i -lt $dirCount; $i++) {
            $off = $dirOffset + $i * 8
            if ($off + 8 -gt $b.Length) { break }
            $result.data_directories += [ordered]@{
                index = $i
                name = $dirNames[$i]
                virtual_address = U32 $b $off
                size = U32 $b ($off + 4)
            }
        }
    }
    if ($null -ne $result.size_of_optional_header) {
        $secOff = $opt + [int]$result.size_of_optional_header
        $result.section_table_offset = $secOff
        $sectionCount = 0
        if ($null -ne $result.number_of_sections) { $sectionCount = [int]$result.number_of_sections }
        $count = [Math]::Min($sectionCount, 32)
        for ($i = 0; $i -lt $count; $i++) {
            $off = $secOff + $i * 40
            if ($off + 8 -gt $b.Length) { break }
            $nameBytes = $b[$off..($off+7)] | Where-Object { $_ -ne 0 }
            if ($nameBytes.Count -eq 0) {
                $result.section_names += ""
            } else {
                $result.section_names += ([System.Text.Encoding]::ASCII.GetString([byte[]]$nameBytes))
            }
        }
    }
    return $result
}

function Parse-Base([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $x = $s.Trim()
    if ($x.StartsWith("0x")) { return [Convert]::ToUInt64($x.Substring(2), 16) }
    return [Convert]::ToUInt64($x, 16)
}

$h = [MemScanNativePe]::OpenProcess(
    [MemScanNativePe]::PROCESS_QUERY_INFORMATION -bor [MemScanNativePe]::PROCESS_VM_READ,
    $false,
    [uint32]$TargetPid
)
if ($h -eq [IntPtr]::Zero) {
    throw "OpenProcess failed for pid=$TargetPid last_error=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

$regions = New-Object System.Collections.Generic.List[object]
$candidates = New-Object System.Collections.Generic.List[object]
$privateExec = New-Object System.Collections.Generic.List[object]
$expectedObj = $null
$expected = Parse-Base $ExpectedBase

try {
    [UInt64]$addr = 0
    [UInt64]$max = if ([IntPtr]::Size -eq 8) { 0x00007ffffffeffff } else { 0x7ffeffff }
    $mbi = New-Object MemScanNativePe+MEMORY_BASIC_INFORMATION64
    $mbiSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"MemScanNativePe+MEMORY_BASIC_INFORMATION64")

    while ($addr -lt $max) {
        $ret = [MemScanNativePe]::VirtualQueryEx($h, [UIntPtr]$addr, [ref]$mbi, [UIntPtr][uint64]$mbiSize)
        if ($ret.ToUInt64() -eq 0) {
            $addr += 0x10000
            continue
        }
        $base = [UInt64]$mbi.BaseAddress
        $size = [UInt64]$mbi.RegionSize
        if ($size -eq 0) { $addr += 0x10000; continue }

        $info = [ordered]@{
            base = Hex64 $base
            allocation_base = Hex64 ([UInt64]$mbi.AllocationBase)
            region_size = $size
            state = StateName $mbi.State
            protect = ProtectName $mbi.Protect
            type = TypeName $mbi.Type
        }
        $regions.Add([pscustomobject]$info) | Out-Null

        $isCommit = ($mbi.State -eq 0x1000)
        $isPrivate = ($mbi.Type -eq 0x20000)
        $isExec = IsExecuteProtect $mbi.Protect
        if ($isCommit -and $isPrivate -and $isExec) {
            $privateExec.Add([pscustomobject]$info) | Out-Null
        }

        if ($isCommit -and (($mbi.Protect -band 0xff) -ne 0x01) -and (($mbi.Protect -band 0x100) -eq 0)) {
            $bytes = Read-Bytes $h $base ([Math]::Min([UInt64]$size, [UInt64]65536))
            if ($bytes) {
                $pe = Analyze-PeHeader $bytes
                if ($pe.mz -or $pe.pe_by_lfanew) {
                    $obj = [ordered]@{}
                    foreach ($k in $info.Keys) { $obj[$k] = $info[$k] }
                    $obj["pe"] = $pe
                    $candidates.Add([pscustomobject]$obj) | Out-Null
                }
            }
        }

        if ($null -ne $expected -and $expected -ge $base -and $expected -lt ($base + $size)) {
            $bytes = Read-Bytes $h $expected ([Math]::Min([UInt64]$size, [UInt64]65536))
            $expectedObj = [ordered]@{}
            foreach ($k in $info.Keys) { $expectedObj[$k] = $info[$k] }
            $expectedObj["expected_base"] = Hex64 $expected
            $expectedObj["pe"] = Analyze-PeHeader $bytes
        }

        $next = $base + $size
        if ($next -le $addr) { $addr += 0x10000 } else { $addr = $next }
    }
}
finally {
    [void][MemScanNativePe]::CloseHandle($h)
}

$out = [ordered]@{
    time = (Get-Date).ToString("o")
    pid = $TargetPid
    expected_base = if ($null -ne $expected) { Hex64 $expected } else { $null }
    summary = [ordered]@{
        total_regions = $regions.Count
        pe_candidate_count = $candidates.Count
        private_executable_region_count = $privateExec.Count
        expected_base_has_mz = if ($expectedObj) { $expectedObj.pe.mz } else { $null }
        expected_base_has_pe_by_lfanew = if ($expectedObj) { $expectedObj.pe.pe_by_lfanew } else { $null }
    }
    expected_base_region = $expectedObj
    pe_candidates = @($candidates | Select-Object -First 80)
    private_executable_regions = @($privateExec | Select-Object -First 120)
}

$json = $out | ConvertTo-Json -Depth 10
if ($OutputPath) {
    $json | Out-File -FilePath $OutputPath -Encoding UTF8
}
$json
