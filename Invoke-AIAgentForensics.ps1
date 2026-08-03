<#
.SYNOPSIS
    Collects and parses Codex and Gemini Antigravity CLI forensic artifacts on Windows.

.DESCRIPTION
    Single-file PowerShell 5.1-compatible collector intended for CrowdStrike Falcon RTR
    and local DFIR use.

    It:
      - discovers Codex and Gemini Antigravity CLI data across local profiles;
      - extracts genuine user prompts from session JSONL files;
      - excludes Codex-generated XML-style context blocks;
      - extracts assistant messages and non-reasoning response items;
      - parses logs_*.sqlite through Windows' built-in winsqlite3.dll;
      - creates normalized CSV and JSONL evidence for offline reconstruction;
      - creates hashes and a retrievable ZIP containing evidence from both agents.

.PARAMETER OutputRoot
    Parent directory for output. Defaults to C:\Windows\Temp.

.PARAMETER UserProfile
    Optional single profile path. Otherwise all profiles under C:\Users that
    contain a .codex or .gemini directory are examined.

.PARAMETER IncludeRawArtifacts
    Copies Codex JSONL/SQLite and Gemini transcript JSONL source artifacts.

.PARAMETER NoZip
    Leaves output as a directory and does not create a ZIP.

.EXAMPLE
    .\Invoke-CodexForensics.ps1 -IncludeRawArtifacts

.EXAMPLE
    .\Invoke-CodexForensics.ps1 -IncludeRawArtifacts
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:WINDIR\Temp",
    [string]$UserProfile = "",
    [switch]$IncludeRawArtifacts,
    [switch]$NoZip
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-PropertyValue {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Truncate-Text {
    param(
        [object]$Value,
        [int]$MaximumLength = 32767
    )

    if ($null -eq $Value) {
        return ""
    }

    $text = [string]$Value

    if ($text.Length -le $MaximumLength) {
        return $text
    }

    return $text.Substring(0, $MaximumLength) + "...[TRUNCATED]"
}

function Test-GeneratedContext {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $true
    }

    # User prompts in observed Codex sessions are plain text. Generated context
    # records, including environment_context and recommended_plugins, begin
    # with an XML-style opening tag.
    return $Text.TrimStart().StartsWith("<")
}

function Convert-UnixTime {
    param(
        [object]$Seconds,
        [object]$Nanoseconds
    )

    if ($null -eq $Seconds -or [string]::IsNullOrWhiteSpace([string]$Seconds)) {
        return ""
    }

    try {
        $epoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
        $date = $epoch.AddSeconds([double]$Seconds)

        if ($null -ne $Nanoseconds -and
            -not [string]::IsNullOrWhiteSpace([string]$Nanoseconds)) {
            $date = $date.AddTicks([long]([double]$Nanoseconds / 100))
        }

        return $date.ToString("o")
    }
    catch {
        return [string]$Seconds
    }
}


function Initialize-WinSqlite {
    if ("WinSqlite.Native" -as [type]) {
        return $true
    }

    $source = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WinSqlite
{
    public static class Native
    {
        private const int SQLITE_OK = 0;
        private const int SQLITE_ROW = 100;
        private const int SQLITE_DONE = 101;
        private const int SQLITE_OPEN_READONLY = 0x00000001;
        private const int SQLITE_OPEN_URI = 0x00000040;

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_open_v2(
            IntPtr filename,
            out IntPtr database,
            int flags,
            IntPtr vfs);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_close(IntPtr database);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_busy_timeout(IntPtr database, int milliseconds);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_prepare_v2(
            IntPtr database,
            IntPtr sql,
            int byteCount,
            out IntPtr statement,
            IntPtr tail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_step(IntPtr statement);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_finalize(IntPtr statement);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_count(IntPtr statement);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_name(IntPtr statement, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_text(IntPtr statement, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_bytes(IntPtr statement, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_column_type(IntPtr statement, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_errmsg(IntPtr database);

        private static IntPtr Utf8Pointer(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value + "\0");
            IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }

        private static string Utf8String(IntPtr pointer)
        {
            if (pointer == IntPtr.Zero)
                return String.Empty;

            int length = 0;
            while (Marshal.ReadByte(pointer, length) != 0)
                length++;

            byte[] bytes = new byte[length];
            Marshal.Copy(pointer, bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }

        private static string ColumnText(IntPtr statement, int index)
        {
            // SQLite type 5 is NULL.
            if (sqlite3_column_type(statement, index) == 5)
                return String.Empty;

            IntPtr pointer = sqlite3_column_text(statement, index);
            if (pointer == IntPtr.Zero)
                return String.Empty;

            int length = sqlite3_column_bytes(statement, index);
            byte[] bytes = new byte[length];
            Marshal.Copy(pointer, bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }

        public static List<Dictionary<string, string>> Query(
            string databasePath,
            string sql)
        {
            IntPtr database = IntPtr.Zero;
            IntPtr statement = IntPtr.Zero;
            IntPtr pathPointer = IntPtr.Zero;
            IntPtr sqlPointer = IntPtr.Zero;

            try
            {
                pathPointer = Utf8Pointer(databasePath);

                int result = sqlite3_open_v2(
                    pathPointer,
                    out database,
                    SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
                    IntPtr.Zero);

                if (result != SQLITE_OK)
                {
                    string message = database == IntPtr.Zero
                        ? "Unable to open SQLite database."
                        : Utf8String(sqlite3_errmsg(database));

                    throw new InvalidOperationException(message);
                }

                sqlite3_busy_timeout(database, 5000);

                sqlPointer = Utf8Pointer(sql);
                result = sqlite3_prepare_v2(
                    database,
                    sqlPointer,
                    -1,
                    out statement,
                    IntPtr.Zero);

                if (result != SQLITE_OK)
                    throw new InvalidOperationException(Utf8String(sqlite3_errmsg(database)));

                int columnCount = sqlite3_column_count(statement);
                string[] names = new string[columnCount];

                for (int i = 0; i < columnCount; i++)
                    names[i] = Utf8String(sqlite3_column_name(statement, i));

                List<Dictionary<string, string>> rows =
                    new List<Dictionary<string, string>>();

                while (true)
                {
                    result = sqlite3_step(statement);

                    if (result == SQLITE_DONE)
                        break;

                    if (result != SQLITE_ROW)
                        throw new InvalidOperationException(Utf8String(sqlite3_errmsg(database)));

                    Dictionary<string, string> row =
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                    for (int i = 0; i < columnCount; i++)
                        row[names[i]] = ColumnText(statement, i);

                    rows.Add(row);
                }

                return rows;
            }
            finally
            {
                if (statement != IntPtr.Zero)
                    sqlite3_finalize(statement);

                if (database != IntPtr.Zero)
                    sqlite3_close(database);

                if (sqlPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(sqlPointer);

                if (pathPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(pathPointer);
            }
        }
    }
}
"@

    try {
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning ("Unable to initialize winsqlite3.dll parser: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Invoke-WinSqliteQuery {
    param(
        [string]$DatabasePath,
        [string]$Query
    )

    $rows = [WinSqlite.Native]::Query($DatabasePath, $Query)

    foreach ($row in $rows) {
        $object = [ordered]@{}

        foreach ($key in $row.Keys) {
            $object[$key] = $row[$key]
        }

        [PSCustomObject]$object
    }
}

function Get-LogCategory {
    param(
        [string]$Target,
        [string]$Body,
        [string]$Level
    )

    $combined = "$Target`n$Body"

    if ($Level -match "^(ERROR|WARN)$") {
        return "ErrorOrWarning"
    }

    if ($combined -match "UserInput|op\.dispatch\.user_input|Submission") {
        return "PromptOrSubmission"
    }

    if ($combined -match "apply_patch|patch[_/ ]|write_file|file[_/ ]?write") {
        return "PatchOrFileChange"
    }

    if ($combined -match "approval|approve|permission") {
        return "Approval"
    }

    if ($combined -match "shell|exec_command|command_execution|powershell|cmd\.exe") {
        return "CommandOrShell"
    }

    if ($combined -match "\bmcp\b|codex_mcp") {
        return "MCP"
    }

    if ($combined -match "plugin/install|plugin/uninstall|recommended_plugins|codex_core_skills") {
        return "PluginOrSkill"
    }

    if ($combined -match "http\.method|api\.path|connecting|connected|sse::responses|websocket") {
        return "NetworkOrAPI"
    }

    if ($combined -match "session_loop|session_task|thread_id|turn_id|session::turn") {
        return "SessionOrTurn"
    }

    if ($combined -match "\btool\b|function_call|tool_call") {
        return "Tool"
    }

    return "Other"
}

function Add-TimelineRow {
    param(
        [System.Collections.ArrayList]$Collection,
        [hashtable]$Values
    )

    $row = [PSCustomObject][ordered]@{
        TimestampUtc     = [string]$Values.TimestampUtc
        Agent            = if ([string]::IsNullOrWhiteSpace([string]$Values.Agent)) { "unknown" } else { [string]$Values.Agent }
        Username         = [string]$Values.Username
        ProfilePath      = [string]$Values.ProfilePath
        Source           = [string]$Values.Source
        Category         = [string]$Values.Category
        Action           = [string]$Values.Action
        ThreadId         = [string]$Values.ThreadId
        TurnId           = [string]$Values.TurnId
        CallId           = [string]$Values.CallId
        ToolName         = [string]$Values.ToolName
        WorkingDirectory = [string]$Values.WorkingDirectory
        Level             = [string]$Values.Level
        Target            = [string]$Values.Target
        Text              = Truncate-Text $Values.Text
        Details           = Truncate-Text $Values.Details
        SourceFile        = [string]$Values.SourceFile
        LineNumber        = [string]$Values.LineNumber
        ProcessUuid       = [string]$Values.ProcessUuid
    }

    [void]$Collection.Add($row)
}

function Copy-RawFile {
    param(
        [string]$Source,
        [string]$ProfileRoot,
        [string]$Username,
        [string]$RawRoot
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        return
    }

    $relativePath = $Source.Substring($ProfileRoot.Length).TrimStart("\")
    $destination = Join-Path (Join-Path $RawRoot $Username) $relativePath
    $destinationDirectory = Split-Path -Parent $destination

    if (-not (Test-Path -LiteralPath $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }

    Copy-Item -LiteralPath $Source -Destination $destination -Force
}

$computerName = $env:COMPUTERNAME

if ([string]::IsNullOrWhiteSpace($computerName)) {
    $computerName = "UNKNOWN"
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$outputDirectory = Join-Path $OutputRoot ("AIAgentDFIR_{0}_{1}" -f $computerName, $timestamp)

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$rawDirectory = Join-Path $outputDirectory "Raw"

if ($IncludeRawArtifacts) {
    New-Item -ItemType Directory -Path $rawDirectory -Force | Out-Null
}

$timeline = New-Object System.Collections.ArrayList
$prompts = New-Object System.Collections.ArrayList
$assistantMessages = New-Object System.Collections.ArrayList
$toolActivity = New-Object System.Collections.ArrayList
$inventory = New-Object System.Collections.ArrayList
$parseErrors = New-Object System.Collections.ArrayList
$profiles = New-Object System.Collections.ArrayList

if (-not [string]::IsNullOrWhiteSpace($UserProfile)) {
    if (-not (Test-Path -LiteralPath $UserProfile -PathType Container)) {
        throw "User profile does not exist: $UserProfile"
    }

    [void]$profiles.Add([PSCustomObject]@{
        Username = Split-Path -Leaf $UserProfile
        ProfilePath = (Resolve-Path -LiteralPath $UserProfile).Path
    })
}
else {
    $excludedProfiles = @(
        "All Users",
        "Default",
        "Default User",
        "Public",
        "defaultuser0",
        "WDAGUtilityAccount"
    )

    foreach ($directory in Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        if ($excludedProfiles -contains $directory.Name) {
            continue
        }

        $codexPath = Join-Path $directory.FullName ".codex"
        $geminiPath = Join-Path $directory.FullName ".gemini"

        if ((Test-Path -LiteralPath $codexPath -PathType Container) -or
            (Test-Path -LiteralPath $geminiPath -PathType Container)) {
            [void]$profiles.Add([PSCustomObject]@{
                Username = $directory.Name
                ProfilePath = $directory.FullName
            })
        }
    }
}

$sqliteParsingEnabled = Initialize-WinSqlite

foreach ($profile in $profiles) {
    $username = [string]$profile.Username
    $profilePath = [string]$profile.ProfilePath
    $codexHome = Join-Path $profilePath ".codex"
    $sessionsPath = Join-Path $codexHome "sessions"

    if (Test-Path -LiteralPath $sessionsPath -PathType Container) {
        $sessionFiles = Get-ChildItem -LiteralPath $sessionsPath `
            -Filter "*.jsonl" -File -Recurse -Force -ErrorAction SilentlyContinue

        foreach ($sessionFile in $sessionFiles) {
            $hash = ""

            try {
                $hash = (Get-FileHash -LiteralPath $sessionFile.FullName -Algorithm SHA256).Hash
            }
            catch {
            }

            [void]$inventory.Add([PSCustomObject][ordered]@{
                Username     = $username
                Agent        = "codex"
                ArtifactType = "CodexSessionJsonl"
                Path         = $sessionFile.FullName
                SizeBytes    = $sessionFile.Length
                CreatedUtc   = $sessionFile.CreationTimeUtc.ToString("o")
                LastWriteUtc = $sessionFile.LastWriteTimeUtc.ToString("o")
                SHA256       = $hash
                Parsed       = $true
            })

            if ($IncludeRawArtifacts) {
                Copy-RawFile -Source $sessionFile.FullName `
                    -ProfileRoot $profilePath `
                    -Username $username `
                    -RawRoot $rawDirectory
            }

            $lineNumber = 0

            foreach ($line in [System.IO.File]::ReadLines($sessionFile.FullName)) {
                $lineNumber++

                if ([string]::IsNullOrWhiteSpace($line)) {
                    continue
                }

                try {
                    $record = $line | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    [void]$parseErrors.Add([PSCustomObject]@{
                        Username   = $username
                        Agent      = "codex"
                        SourceFile = $sessionFile.FullName
                        LineNumber = $lineNumber
                        Error      = $_.Exception.Message
                    })

                    continue
                }

                $recordType = [string](Get-PropertyValue $record "type")
                $recordTimestamp = [string](Get-PropertyValue $record "timestamp")
                $payload = Get-PropertyValue $record "payload"

                if ($null -eq $payload) {
                    continue
                }

                $payloadType = [string](Get-PropertyValue $payload "type")
                $role = [string](Get-PropertyValue $payload "role")
                $threadId = [string](Get-PropertyValue $payload "thread_id")
                $turnId = ""
                $callId = [string](Get-PropertyValue $payload "call_id")
                $toolName = [string](Get-PropertyValue $payload "name")
                $workingDirectory = [string](Get-PropertyValue $payload "cwd")

                $metadata = Get-PropertyValue $payload "internal_chat_message_metadata_passthrough"

                if ($null -ne $metadata) {
                    $turnId = [string](Get-PropertyValue $metadata "turn_id")
                }

                if ($recordType -eq "response_item" -and
                    $payloadType -eq "message" -and
                    $role -eq "user") {

                    $promptParts = @()

                    foreach ($contentItem in @(Get-PropertyValue $payload "content")) {
                        if ($null -eq $contentItem) {
                            continue
                        }

                        $contentType = [string](Get-PropertyValue $contentItem "type")
                        $text = [string](Get-PropertyValue $contentItem "text")

                        if ($contentType -eq "input_text" -and
                            -not (Test-GeneratedContext $text)) {
                            $promptParts += $text.Trim()
                        }
                    }

                    if ($promptParts.Count -gt 0) {
                        $promptText = $promptParts -join "`r`n"

                        [void]$prompts.Add([PSCustomObject][ordered]@{
                            TimestampUtc = $recordTimestamp
                            Agent        = "codex"
                            Username     = $username
                            TurnId       = $turnId
                            Prompt       = Truncate-Text $promptText
                            SessionFile  = $sessionFile.FullName
                            LineNumber   = $lineNumber
                        })

                        Add-TimelineRow -Collection $timeline -Values @{
                            TimestampUtc = $recordTimestamp
                        Agent = "codex"
                            Username = $username
                            ProfilePath = $profilePath
                            Source = "SessionJsonl"
                            Category = "Prompt"
                            Action = "UserPrompt"
                            ThreadId = $threadId
                            TurnId = $turnId
                            CallId = $callId
                            ToolName = ""
                            WorkingDirectory = $workingDirectory
                            Level = ""
                            Target = ""
                            Text = $promptText
                            Details = ""
                            SourceFile = $sessionFile.FullName
                            LineNumber = $lineNumber
                            ProcessUuid = ""
                        }
                    }

                    continue
                }

                if ($recordType -eq "response_item" -and
                    $payloadType -eq "message" -and
                    $role -eq "assistant") {

                    $messageParts = @()

                    foreach ($contentItem in @(Get-PropertyValue $payload "content")) {
                        if ($null -eq $contentItem) {
                            continue
                        }

                        $contentType = [string](Get-PropertyValue $contentItem "type")
                        $text = [string](Get-PropertyValue $contentItem "text")

                        if (($contentType -eq "output_text" -or
                             $contentType -eq "input_text") -and
                            -not [string]::IsNullOrWhiteSpace($text)) {
                            $messageParts += $text.Trim()
                        }
                    }

                    if ($messageParts.Count -gt 0) {
                        $messageText = $messageParts -join "`r`n"

                        [void]$assistantMessages.Add([PSCustomObject][ordered]@{
                            TimestampUtc = $recordTimestamp
                            Agent        = "codex"
                            Username     = $username
                            TurnId       = $turnId
                            Message      = Truncate-Text $messageText
                            SessionFile  = $sessionFile.FullName
                            LineNumber   = $lineNumber
                        })

                        Add-TimelineRow -Collection $timeline -Values @{
                            TimestampUtc = $recordTimestamp
                        Agent = "codex"
                            Username = $username
                            ProfilePath = $profilePath
                            Source = "SessionJsonl"
                            Category = "AssistantMessage"
                            Action = "AssistantOutput"
                            ThreadId = $threadId
                            TurnId = $turnId
                            CallId = $callId
                            ToolName = ""
                            WorkingDirectory = $workingDirectory
                            Level = ""
                            Target = ""
                            Text = $messageText
                            Details = ""
                            SourceFile = $sessionFile.FullName
                            LineNumber = $lineNumber
                            ProcessUuid = ""
                        }
                    }

                    continue
                }

                if ($recordType -eq "response_item" -and
                    $payloadType -ne "reasoning") {

                    $detailsObject = [ordered]@{
                        PayloadType = $payloadType
                        Name = $toolName
                        Arguments = Get-PropertyValue $payload "arguments"
                        Action = Get-PropertyValue $payload "action"
                        Command = Get-PropertyValue $payload "command"
                        Output = Get-PropertyValue $payload "output"
                    }

                    $detailsJson = $detailsObject | ConvertTo-Json -Compress -Depth 20
                    $commandText = [string](Get-PropertyValue $payload "command")

                    [void]$toolActivity.Add([PSCustomObject][ordered]@{
                        TimestampUtc     = $recordTimestamp
                        Agent            = "codex"
                        Username         = $username
                        PayloadType      = $payloadType
                        ToolName         = $toolName
                        CallId           = $callId
                        TurnId           = $turnId
                        WorkingDirectory = $workingDirectory
                        Details          = Truncate-Text $detailsJson
                        SessionFile      = $sessionFile.FullName
                        LineNumber       = $lineNumber
                    })

                    Add-TimelineRow -Collection $timeline -Values @{
                        TimestampUtc = $recordTimestamp
                        Agent = "codex"
                        Username = $username
                        ProfilePath = $profilePath
                        Source = "SessionJsonl"
                        Category = "ToolOrAction"
                        Action = $payloadType
                        ThreadId = $threadId
                        TurnId = $turnId
                        CallId = $callId
                        ToolName = $toolName
                        WorkingDirectory = $workingDirectory
                        Level = ""
                        Target = ""
                        Text = $commandText
                        Details = $detailsJson
                        SourceFile = $sessionFile.FullName
                        LineNumber = $lineNumber
                        ProcessUuid = ""
                    }
                }
            }
        }
    }

    $sqliteFiles = Get-ChildItem -LiteralPath $codexHome `
        -Filter "logs_*.sqlite" -File -Force -ErrorAction SilentlyContinue

    foreach ($database in $sqliteFiles) {
        $hash = ""

        try {
            $hash = (Get-FileHash -LiteralPath $database.FullName -Algorithm SHA256).Hash
        }
        catch {
        }

        $databaseParsingEnabled = $sqliteParsingEnabled

        [void]$inventory.Add([PSCustomObject][ordered]@{
            Username     = $username
            Agent        = "codex"
            ArtifactType = "CodexRuntimeLogSqlite"
            Path         = $database.FullName
            SizeBytes    = $database.Length
            CreatedUtc   = $database.CreationTimeUtc.ToString("o")
            LastWriteUtc = $database.LastWriteTimeUtc.ToString("o")
            SHA256       = $hash
            Parsed       = $databaseParsingEnabled
        })

        if ($IncludeRawArtifacts) {
            Copy-RawFile -Source $database.FullName `
                -ProfileRoot $profilePath `
                -Username $username `
                -RawRoot $rawDirectory

            foreach ($suffix in @("-wal", "-shm")) {
                $sidecar = $database.FullName + $suffix

                if (Test-Path -LiteralPath $sidecar -PathType Leaf) {
                    Copy-RawFile -Source $sidecar `
                        -ProfileRoot $profilePath `
                        -Username $username `
                        -RawRoot $rawDirectory
                }
            }
        }

        if (-not $databaseParsingEnabled) {
            continue
        }

        try {
            $query = "SELECT id,ts,ts_nanos,level,target,feedback_log_body,module_path,file,line,thread_id,process_uuid,estimated_bytes FROM logs ORDER BY ts,ts_nanos,id;"
            $logRows = Invoke-WinSqliteQuery `
                -DatabasePath $database.FullName `
                -Query $query

            if ($null -eq $logRows) {
                continue
            }

            foreach ($logRow in $logRows) {
                $body = [string]$logRow.feedback_log_body
                $target = [string]$logRow.target
                $level = [string]$logRow.level
                $category = Get-LogCategory -Target $target -Body $body -Level $level
                $action = "LogEvent"

                switch ($category) {
                    "PromptOrSubmission" { $action = "UserInputOrSubmission" }
                    "PatchOrFileChange"  { $action = "PatchOrFileChange" }
                    "Approval"           { $action = "ApprovalEvent" }
                    "CommandOrShell"     { $action = "CommandEvent" }
                    "MCP"                { $action = "McpEvent" }
                    "PluginOrSkill"      { $action = "PluginOrSkillEvent" }
                    "NetworkOrAPI"       { $action = "NetworkEvent" }
                    "SessionOrTurn"      { $action = "SessionEvent" }
                    "Tool"               { $action = "ToolEvent" }
                    "ErrorOrWarning"     { $action = "RuntimeIssue" }
                }

                Add-TimelineRow -Collection $timeline -Values @{
                    TimestampUtc = Convert-UnixTime $logRow.ts $logRow.ts_nanos
                        Agent = "codex"
                    Username = $username
                    ProfilePath = $profilePath
                    Source = "RuntimeSqlite"
                    Category = $category
                    Action = $action
                    ThreadId = [string]$logRow.thread_id
                    TurnId = ""
                    CallId = ""
                    ToolName = ""
                    WorkingDirectory = ""
                    Level = $level
                    Target = $target
                    Text = $body
                    Details = ("module={0}; source={1}:{2}; log_id={3}; estimated_bytes={4}" -f `
                        $logRow.module_path,
                        $logRow.file,
                        $logRow.line,
                        $logRow.id,
                        $logRow.estimated_bytes)
                    SourceFile = $database.FullName
                    LineNumber = ""
                    ProcessUuid = [string]$logRow.process_uuid
                }
            }
        }
        catch {
            [void]$parseErrors.Add([PSCustomObject]@{
                Username   = $username
                Agent      = "codex"
                SourceFile = $database.FullName
                LineNumber = ""
                Error      = $_.Exception.Message
            })
        }
    }

    if ($IncludeRawArtifacts) {
        foreach ($name in @(
            "config.toml",
            "state_5.sqlite",
            "session_index.jsonl"
        )) {
            $candidate = Join-Path $codexHome $name

            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                Copy-RawFile -Source $candidate `
                    -ProfileRoot $profilePath `
                    -Username $username `
                    -RawRoot $rawDirectory
            }
        }
    }
}


function Get-GeminiUserRequest {
    param([string]$Content)

    if ([string]::IsNullOrWhiteSpace($Content)) {
        return ""
    }

    $match = [regex]::Match(
        $Content,
        "<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>",
        [System.Text.RegularExpressions.RegexOptions]::Singleline -bor
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }

    return $Content.Trim()
}

function Get-GeminiSessionId {
    param([string]$TranscriptPath)

    $match = [regex]::Match(
        $TranscriptPath,
        "[\\/]brain[\\/]([^\\/]+)[\\/]\.system_generated[\\/]logs[\\/]",
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($match.Success) {
        return $match.Groups[1].Value
    }

    return (Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $TranscriptPath)))
}

function Convert-GeminiToolArguments {
    param([object]$Arguments)

    if ($null -eq $Arguments) {
        return "{}"
    }

    $safe = [ordered]@{}

    foreach ($property in $Arguments.PSObject.Properties) {
        $name = [string]$property.Name
        $value = $property.Value

        if ($name -in @("CodeContent", "Base64", "ImageBytes")) {
            $textValue = [string]$value
            $safe[$name + "Length"] = $textValue.Length

            if (-not [string]::IsNullOrEmpty($textValue)) {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($textValue)
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $safe[$name + "SHA256"] = (
                        [BitConverter]::ToString($sha.ComputeHash($bytes))
                    ).Replace("-", "")
                }
                finally {
                    $sha.Dispose()
                }
            }

            continue
        }

        $safe[$name] = $value
    }

    return ($safe | ConvertTo-Json -Compress -Depth 20)
}

function Collect-GeminiAntigravityArtifacts {
    param(
        [string]$ProfilePath,
        [string]$Username
    )

    $geminiLogsRoot = Join-Path $ProfilePath ".gemini\antigravity-cli\brain"

    if (-not (Test-Path -LiteralPath $geminiLogsRoot -PathType Container)) {
        return
    }

    $transcriptFiles = Get-ChildItem -LiteralPath $geminiLogsRoot `
        -Filter "transcript_full.jsonl" -File -Recurse -Force `
        -ErrorAction SilentlyContinue | Where-Object {
            $_.FullName -match "[\\/]\.system_generated[\\/]logs[\\/]transcript_full\.jsonl$"
        }

    foreach ($transcriptFile in $transcriptFiles) {
        $hash = ""
        try {
            $hash = (Get-FileHash -LiteralPath $transcriptFile.FullName -Algorithm SHA256).Hash
        }
        catch {
        }

        [void]$inventory.Add([PSCustomObject][ordered]@{
            Username     = $Username
            Agent        = "gemini"
            ArtifactType = "GeminiAntigravityTranscriptJsonl"
            Path         = $transcriptFile.FullName
            SizeBytes    = $transcriptFile.Length
            CreatedUtc   = $transcriptFile.CreationTimeUtc.ToString("o")
            LastWriteUtc = $transcriptFile.LastWriteTimeUtc.ToString("o")
            SHA256       = $hash
            Parsed       = $true
        })

        if ($IncludeRawArtifacts) {
            Copy-RawFile -Source $transcriptFile.FullName `
                -ProfileRoot $ProfilePath `
                -Username $Username `
                -RawRoot $rawDirectory

            $compactTranscript = Join-Path $transcriptFile.DirectoryName "transcript.jsonl"
            if (Test-Path -LiteralPath $compactTranscript -PathType Leaf) {
                Copy-RawFile -Source $compactTranscript `
                    -ProfileRoot $ProfilePath `
                    -Username $Username `
                    -RawRoot $rawDirectory
            }
        }

        $sessionId = Get-GeminiSessionId $transcriptFile.FullName
        $lineNumber = 0

        foreach ($line in [System.IO.File]::ReadLines($transcriptFile.FullName)) {
            $lineNumber++
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            try {
                $record = $line | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                [void]$parseErrors.Add([PSCustomObject]@{
                    Username   = $Username
                    Agent      = "gemini"
                    SourceFile = $transcriptFile.FullName
                    LineNumber = $lineNumber
                    Error      = $_.Exception.Message
                })
                continue
            }

            $createdAt = [string](Get-PropertyValue $record "created_at")
            $stepIndex = [string](Get-PropertyValue $record "step_index")
            $source = ([string](Get-PropertyValue $record "source")).ToUpperInvariant()
            $recordType = ([string](Get-PropertyValue $record "type")).ToUpperInvariant()
            $status = [string](Get-PropertyValue $record "status")
            $content = [string](Get-PropertyValue $record "content")
            $thinking = [string](Get-PropertyValue $record "thinking")

            if ($source -eq "USER_EXPLICIT" -and $recordType -eq "USER_INPUT") {
                $promptText = Get-GeminiUserRequest $content
                if (-not [string]::IsNullOrWhiteSpace($promptText)) {
                    [void]$prompts.Add([PSCustomObject][ordered]@{
                        TimestampUtc = $createdAt
                        Agent        = "gemini"
                        Username     = $Username
                        TurnId       = $stepIndex
                        Prompt       = Truncate-Text $promptText
                        SessionFile  = $transcriptFile.FullName
                        LineNumber   = $lineNumber
                    })

                    Add-TimelineRow -Collection $timeline -Values @{
                        TimestampUtc = $createdAt
                        Agent = "gemini"
                        Username = $Username
                        ProfilePath = $ProfilePath
                        Source = "GeminiAntigravityJsonl"
                        Category = "Prompt"
                        Action = "UserInput"
                        ThreadId = $sessionId
                        TurnId = $stepIndex
                        CallId = ""
                        ToolName = ""
                        WorkingDirectory = ""
                        Level = $status
                        Target = ""
                        Text = $promptText
                        Details = "record_type=USER_INPUT"
                        SourceFile = $transcriptFile.FullName
                        LineNumber = $lineNumber
                        ProcessUuid = ""
                    }
                }
                continue
            }

            if ($source -eq "MODEL" -and
                $recordType -eq "PLANNER_RESPONSE" -and
                -not [string]::IsNullOrWhiteSpace($content)) {
                [void]$assistantMessages.Add([PSCustomObject][ordered]@{
                    TimestampUtc = $createdAt
                    Agent        = "gemini"
                    Username     = $Username
                    TurnId       = $stepIndex
                    Message      = Truncate-Text $content.Trim()
                    SessionFile  = $transcriptFile.FullName
                    LineNumber   = $lineNumber
                })

                Add-TimelineRow -Collection $timeline -Values @{
                    TimestampUtc = $createdAt
                    Agent = "gemini"
                    Username = $Username
                    ProfilePath = $ProfilePath
                    Source = "GeminiAntigravityJsonl"
                    Category = "AssistantMessage"
                    Action = "AssistantOutput"
                    ThreadId = $sessionId
                    TurnId = $stepIndex
                    CallId = ""
                    ToolName = ""
                    WorkingDirectory = ""
                    Level = $status
                    Target = ""
                    Text = $content.Trim()
                    Details = "record_type=PLANNER_RESPONSE"
                    SourceFile = $transcriptFile.FullName
                    LineNumber = $lineNumber
                    ProcessUuid = ""
                }
            }

            $toolCalls = @(Get-PropertyValue $record "tool_calls")
            $toolIndex = 0
            foreach ($toolCall in $toolCalls) {
                if ($null -eq $toolCall) { continue }
                $toolName = [string](Get-PropertyValue $toolCall "name")
                $arguments = Get-PropertyValue $toolCall "args"
                $command = [string](Get-PropertyValue $arguments "CommandLine")
                $cwd = [string](Get-PropertyValue $arguments "Cwd")
                $target = [string](Get-PropertyValue $arguments "TargetFile")
                if ([string]::IsNullOrWhiteSpace($target)) {
                    $target = [string](Get-PropertyValue $arguments "DirectoryPath")
                }
                if ([string]::IsNullOrWhiteSpace($target)) {
                    $target = [string](Get-PropertyValue $arguments "Target")
                }
                if ([string]::IsNullOrWhiteSpace($target)) {
                    $target = [string](Get-PropertyValue $arguments "ImageName")
                }

                $safeArguments = Convert-GeminiToolArguments $arguments
                $details = ([ordered]@{
                    ToolName = $toolName
                    Arguments = ($safeArguments | ConvertFrom-Json)
                } | ConvertTo-Json -Compress -Depth 20)

                [void]$toolActivity.Add([PSCustomObject][ordered]@{
                    TimestampUtc     = $createdAt
                    Agent            = "gemini"
                    Username         = $Username
                    PayloadType      = $recordType
                    ToolName         = $toolName
                    CallId           = ("{0}:{1}" -f $stepIndex, $toolIndex)
                    TurnId           = $stepIndex
                    WorkingDirectory = $cwd
                    Details          = Truncate-Text $details
                    SessionFile      = $transcriptFile.FullName
                    LineNumber       = $lineNumber
                })

                $action = $toolName
                switch ($toolName) {
                    "run_command"    { $action = "exec_command" }
                    "write_to_file"  { $action = "write_file" }
                    "list_dir"       { $action = "read_directory" }
                    "ask_permission" { $action = "approval_request" }
                }

                Add-TimelineRow -Collection $timeline -Values @{
                    TimestampUtc = $createdAt
                    Agent = "gemini"
                    Username = $Username
                    ProfilePath = $ProfilePath
                    Source = "GeminiAntigravityJsonl"
                    Category = "ToolOrAction"
                    Action = $action
                    ThreadId = $sessionId
                    TurnId = $stepIndex
                    CallId = ("{0}:{1}" -f $stepIndex, $toolIndex)
                    ToolName = $toolName
                    WorkingDirectory = $cwd
                    Level = $status
                    Target = $target
                    Text = $command
                    Details = $details
                    SourceFile = $transcriptFile.FullName
                    LineNumber = $lineNumber
                    ProcessUuid = ""
                }
                $toolIndex++
            }

            if (-not [string]::IsNullOrWhiteSpace($thinking)) {
                Add-TimelineRow -Collection $timeline -Values @{
                    TimestampUtc = $createdAt
                    Agent = "gemini"
                    Username = $Username
                    ProfilePath = $ProfilePath
                    Source = "GeminiAntigravityJsonl"
                    Category = "SessionOrTurn"
                    Action = "ModelReasoning"
                    ThreadId = $sessionId
                    TurnId = $stepIndex
                    CallId = ""
                    ToolName = ""
                    WorkingDirectory = ""
                    Level = $status
                    Target = ""
                    Text = ""
                    Details = $thinking
                    SourceFile = $transcriptFile.FullName
                    LineNumber = $lineNumber
                    ProcessUuid = ""
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($content) -and
                -not ($source -eq "MODEL" -and $recordType -eq "PLANNER_RESPONSE")) {
                $category = "SessionOrTurn"
                if ($source -eq "MODEL" -and $recordType -notin @("CHECKPOINT", "CONVERSATION_HISTORY")) {
                    $category = "ToolOrAction"
                }

                Add-TimelineRow -Collection $timeline -Values @{
                    TimestampUtc = $createdAt
                    Agent = "gemini"
                    Username = $Username
                    ProfilePath = $ProfilePath
                    Source = "GeminiAntigravityJsonl"
                    Category = $category
                    Action = $recordType
                    ThreadId = $sessionId
                    TurnId = $stepIndex
                    CallId = ""
                    ToolName = ""
                    WorkingDirectory = ""
                    Level = $status
                    Target = ""
                    Text = ""
                    Details = $content
                    SourceFile = $transcriptFile.FullName
                    LineNumber = $lineNumber
                    ProcessUuid = ""
                }
            }
        }
    }
}

foreach ($profile in $profiles) {
    Collect-GeminiAntigravityArtifacts `
        -ProfilePath ([string]$profile.ProfilePath) `
        -Username ([string]$profile.Username)
}


function Export-JsonLines {
    param(
        [object[]]$InputObject,
        [string]$Path
    )

    $writer = New-Object System.IO.StreamWriter(
        $Path,
        $false,
        (New-Object System.Text.UTF8Encoding($false))
    )

    try {
        foreach ($item in $InputObject) {
            $json = $item | ConvertTo-Json -Compress -Depth 20
            $writer.WriteLine($json)
        }
    }
    finally {
        $writer.Dispose()
    }
}

$timelinePath = Join-Path $outputDirectory "AI_Agent_Timeline.csv"
$promptsPath = Join-Path $outputDirectory "AI_Agent_Prompts.csv"
$assistantPath = Join-Path $outputDirectory "AI_Agent_AssistantMessages.csv"
$toolPath = Join-Path $outputDirectory "AI_Agent_ToolActivity.csv"
$inventoryPath = Join-Path $outputDirectory "Artifact_Inventory.csv"
$errorPath = Join-Path $outputDirectory "Parse_Errors.csv"
$summaryPath = Join-Path $outputDirectory "Summary.json"
$timelineJsonlPath = Join-Path $outputDirectory "AI_Agent_Timeline.jsonl"
$promptsJsonlPath = Join-Path $outputDirectory "AI_Agent_Prompts.jsonl"
$assistantJsonlPath = Join-Path $outputDirectory "AI_Agent_AssistantMessages.jsonl"
$toolJsonlPath = Join-Path $outputDirectory "AI_Agent_ToolActivity.jsonl"

$timeline |
    Sort-Object TimestampUtc, Username, SourceFile, LineNumber |
    Export-Csv -LiteralPath $timelinePath -NoTypeInformation -Encoding UTF8

$prompts |
    Sort-Object TimestampUtc, Username |
    Export-Csv -LiteralPath $promptsPath -NoTypeInformation -Encoding UTF8

$assistantMessages |
    Sort-Object TimestampUtc, Username |
    Export-Csv -LiteralPath $assistantPath -NoTypeInformation -Encoding UTF8

$toolActivity |
    Sort-Object TimestampUtc, Username |
    Export-Csv -LiteralPath $toolPath -NoTypeInformation -Encoding UTF8

$inventory |
    Sort-Object Username, ArtifactType, Path |
    Export-Csv -LiteralPath $inventoryPath -NoTypeInformation -Encoding UTF8

Export-JsonLines `
    -InputObject @($timeline | Sort-Object TimestampUtc, Username, SourceFile, LineNumber) `
    -Path $timelineJsonlPath

Export-JsonLines `
    -InputObject @($prompts | Sort-Object TimestampUtc, Username) `
    -Path $promptsJsonlPath

Export-JsonLines `
    -InputObject @($assistantMessages | Sort-Object TimestampUtc, Username) `
    -Path $assistantJsonlPath

Export-JsonLines `
    -InputObject @($toolActivity | Sort-Object TimestampUtc, Username) `
    -Path $toolJsonlPath

if ($parseErrors.Count -gt 0) {
    $parseErrors |
        Export-Csv -LiteralPath $errorPath -NoTypeInformation -Encoding UTF8
}

$categoryCounts = @{}
$agentCounts = @{}

foreach ($group in $timeline | Group-Object Category) {
    $categoryCounts[$group.Name] = $group.Count
}

foreach ($group in $timeline | Group-Object {
    $agentProperty = $_.PSObject.Properties["Agent"]
    if ($null -eq $agentProperty -or [string]::IsNullOrWhiteSpace([string]$agentProperty.Value)) {
        return "unknown"
    }
    return [string]$agentProperty.Value
}) {
    $agentCounts[$group.Name] = $group.Count
}

$profileNames = @()

foreach ($profile in $profiles) {
    $profileNames += [string]$profile.Username
}

$summary = [ordered]@{
    ComputerName          = $computerName
    CollectionTimeUtc     = (Get-Date).ToUniversalTime().ToString("o")
    RunningAs             = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    ProfilesExamined      = $profiles.Count
    ProfileNames          = $profileNames
    SqliteParser          = "winsqlite3.dll"
    SqliteParsingEnabled  = [bool]$sqliteParsingEnabled
    RawArtifactsIncluded  = [bool]$IncludeRawArtifacts
    ArtifactCount         = $inventory.Count
    TimelineEventCount    = $timeline.Count
    PromptCount           = $prompts.Count
    AssistantMessageCount = $assistantMessages.Count
    ToolActivityCount     = $toolActivity.Count
    ParseErrorCount       = $parseErrors.Count
    CategoryCounts        = $categoryCounts
    AgentCounts           = $agentCounts
    SupportedAgents       = @("codex", "gemini-antigravity")
    OutputDirectory       = $outputDirectory
    ReportGeneratorInput  = $timelineJsonlPath
}

$summary |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $summaryPath -Encoding UTF8

$zipPath = ""

if (-not $NoZip) {
    $zipPath = "$outputDirectory.zip"

    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }

    Compress-Archive -Path (Join-Path $outputDirectory "*") `
        -DestinationPath $zipPath `
        -CompressionLevel Optimal `
        -Force
}

$codexEventCount = @($timeline | Where-Object {
    $property = $_.PSObject.Properties["Agent"]
    $null -ne $property -and [string]$property.Value -eq "codex"
}).Count

$geminiEventCount = @($timeline | Where-Object {
    $property = $_.PSObject.Properties["Agent"]
    $null -ne $property -and [string]$property.Value -eq "gemini"
}).Count

Write-Output "AI_AGENT_DFIR_STATUS=SUCCESS"
Write-Output ("COMPUTER={0}" -f $computerName)
Write-Output ("PROFILES={0}" -f $profiles.Count)
Write-Output ("CODEX_EVENTS={0}" -f $codexEventCount)
Write-Output ("GEMINI_EVENTS={0}" -f $geminiEventCount)
Write-Output ("PROMPTS={0}" -f $prompts.Count)
Write-Output ("ASSISTANT_MESSAGES={0}" -f $assistantMessages.Count)
Write-Output ("TOOL_EVENTS={0}" -f $toolActivity.Count)
Write-Output ("TIMELINE_EVENTS={0}" -f $timeline.Count)
Write-Output ("PARSE_ERRORS={0}" -f $parseErrors.Count)
Write-Output ("SQLITE_PARSED={0}" -f [bool]$sqliteParsingEnabled)
Write-Output ("OUTPUT_DIRECTORY={0}" -f $outputDirectory)
Write-Output ("REPORT_INPUT={0}" -f $timelineJsonlPath)

if (-not [string]::IsNullOrWhiteSpace($zipPath)) {
    Write-Output ("RETRIEVE_FILE={0}" -f $zipPath)
}
