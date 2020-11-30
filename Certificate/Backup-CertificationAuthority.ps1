function Backup-CertificationAuthority {
[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[IO.DirectoryInfo]$Path,
		[ValidateSet("Full","Incremental")]
		[string]$Type = "Full",
		[string]$Password,
		[switch]$BackupKey,
		[switch]$KeepLog,
		[switch]$Extended,
		[switch]$Force
	)

	if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
	if ($PSBoundParameters.Debug) {
		$Host.PrivateData.DebugForegroundColor = "Cyan"
		$DebugPreference = "continue"
	}
#region Defining low-level APIs

$cadmsignature = @"
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CertSrvIsServerOnline(
	string pwszServerName,
	ref bool pfServerOnline
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupPrepare(
	string pwszServerName,
	uint grbitJet,
	uint dwBackupFlags,
	ref IntPtr phbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupGetDatabaseNames(
	IntPtr hbc,
	ref IntPtr ppwszzAttachmentInformation,
	ref uint pcbSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupGetBackupLogs(
	IntPtr hbc,
	ref IntPtr ppwszzBackupLogFiles,
	ref uint pcbSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupGetDynamicFileList(
	IntPtr hbc,
	ref IntPtr ppwszzFileList,
	ref uint pcbSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupOpenFile(
	IntPtr hbc,
	string pwszAttachmentName,
	int cbReadHintSize,
	ref Int64 pliFileSize
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupRead(
	IntPtr hbc,
	IntPtr pvBuffer,
	int cbBuffer,
	ref int pcbRead
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupClose(
	IntPtr hbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupTruncateLogs(
	IntPtr hbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupEnd(
	IntPtr phbc
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvBackupFree(
	IntPtr pv
);
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int CertSrvRestoreGetDatabaseLocations(
	IntPtr hbc,
	ref IntPtr ppwszzDatabaseLocationList,
	ref uint pcbSize
);
"@
#endregion

#region add defined types
	try {Add-Type -MemberDefinition $cadmsignature -Namespace PKI -Name CertAdm}
	catch {break}
#endregion

#region Path checking
	if (Test-Path $Path) {
		if (Test-Path $Path\DataBase) {
			if ($Force) {
				try {
					Remove-Item $Path\DataBase -Recurse -Force -ErrorAction Stop
					$BackupDir = New-Item -Name DataBase -ItemType directory -Path $Path -Force -ErrorAction Stop
				} catch {
					Write-Error -Category InvalidOperation -ErrorId "InvalidOperationDeleteException" `
					-ErrorAction Stop -Message $Error[0].Exception
				}
			} else {
				Write-Error -Category ResourceExists -ErrorId "ResourceExistsException" `
				-ErrorAction Stop -Message "The path '$Path\DataBase' already exist."
			}
		} else {
			$BackupDir = New-Item -Name DataBase -ItemType directory -Path $Path -Force -ErrorAction Stop
		}
	} else {
		try {$BackupDir = New-Item -Name DataBase -ItemType directory -Path $Path -Force -ErrorAction Stop}
		catch {
			Write-Error -Category ObjectNotFound -ErrorId "PathNotFoundException" `
			-ErrorAction Stop -Message "Cannot create object in '$Path'"
		}
	}
#endregion

#region helper functions
	function Split-BackupPath ([Byte[]]$Bytes) {
		$SB = New-Object System.Text.StringBuilder
		$bytes1 = $bytes | ForEach-Object {"{0:X2}" -f $_}
		for ($n = 0; $n -lt $bytes1.count; $n = $n + 2) {
			[void]$SB.Append([char](Invoke-Expression 0x$(($bytes1[$n+1]) + ($bytes1[$n]))))
		}
		$SB.ToString().Split("`0",[StringSplitOptions]::RemoveEmptyEntries)
	}
	function __BackupKey ($Password) {
		$CertConfig = New-Object -ComObject CertificateAuthority.Config
		try {$local = $CertConfig.GetConfig(3)}
		catch { }
		if ($local -ne $null) {
			$name = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration' -Name Active).Active
			$StoreCerts = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
			$Certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
			$TempCerts = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
			$Store = New-Object Security.Cryptography.X509Certificates.X509Store "My", "LocalMachine"
			$Store.Open("ReadOnly")
			$StoreCerts = $Store.Certificates
			$Store.Close()
			$Certs = $StoreCerts.Find("FindBySubjectName",$name,$true)
			$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
			$chain.ChainPolicy.RevocationMode = "NoCheck"
			$Certs | ForEach-Object {
				[void]$chain.Build($_)
				if ($chain.ChainElements.Count -ge 1) {
					for ($n = 1; $n -lt $chain.ChainElements.Count; $n++) {
						[void]$TempCerts.Add($chain.ChainElements[$n].Certificate)
					}
				}
				$chain.Reset()
			}
			if ($TempCerts.Count -gt 0) {
				$Certs.AddRange([Security.Cryptography.X509Certificates.X509Certificate2[]]($TempCerts | Select-Object -Unique))
			}
			try {[IO.File]::WriteAllBytes("$Path\$Name.p12",$Certs.Export("pfx",$Password))}
			finally {$StoreCerts, $Certs, $TempCerts | ForEach-Object {$_.Clear()}}
		}
	}
	# helper function for backup routine
	function __BackupRoutine ($phbc,$File,$BackupDir,$pvBuffer, $cbBuffer, $FileType) {
		$n = 1
		Write-Debug "Read buffer address: $pvBuffer"
		$FileName = Get-Item $File -ErrorAction SilentlyContinue
		$pliFileSize = 0
		Write-Debug "Open current item: $file"
		# open DB file. I set 0 for cbReadHintSize to allow system to automatically select proper buffer size
		$hresult = [PKI.CertAdm]::CertSrvBackupOpenFile($phbc,$File,$cbBuffer,[ref]$pliFileSize)
		if ($hresult -ne 0) {
			$StatusObject.Status = 0x8007004
			__status $StatusObject
			break
		}
		Write-Debug "Current item size in bytes: $pliFileSize"
		$BackupFile = New-Item -Name $FileName.Name -ItemType file -Path $BackupDir -Force -ErrorAction Stop
		$FS = New-Object IO.FileStream $BackupFile,"append","write"
		[int]$pcbRead = 0
		$complete = 0
		$Name = (Get-Item $File -Force -ErrorAction SilentlyContinue).Name
		while (!$last) {
			$n++
			[int]$percent = $complete / $pliFileSize * 100
			Write-Progress -Activity "Backing up database file '$name' " -CurrentOperation InnerLoop -PercentComplete $percent `
			-Status "$percent% complete"
			$hresult = [PKI.CertAdm]::CertSrvBackupRead($phbc,$pvBuffer,$cbBuffer,[ref]$pcbRead)
			if ($hresult -ne 0) {
				$StatusObject.Status = 0x800701e
				__status $StatusObject
				break
			}
			if ($FileType -eq "database") {$script:Size += $pcbRead}
			Write-Debug "Reading $n portion of $pcbRead bytes"
			$uBuffer = New-Object byte[] -ArgumentList $pcbRead
			[Runtime.InteropServices.Marshal]::Copy($pvBuffer,$uBuffer,0,$pcbRead)
			$FS.Write($uBuffer,0,$uBuffer.Length)
			$complete += $pcbRead
			if ($pcbRead -lt $cbBuffer) {$last = $true}
		}
		Write-Debug "Closing current item: $file"
		$FS.Close()
		$hresult = [PKI.CertAdm]::CertSrvBackupClose($phbc)
		Write-Debug "Current item '$BackupFile' is closed: $(!$hresult)"
		# relelase managed and unmanaged buffers
		Remove-Variable uBuffer
	}
	function __status ($StatusObject) {
		try {$StatusObject.StatusMessage = [PKI.Utils.Error]::GetMessage($StatusObject.Status)}
		catch { }
		Write-Verbose "Clearing resources"
		$hresult = [PKI.CertAdm]::CertSrvBackupEnd($phbc)
		Write-Debug "Backup sent to end state: $(!$hresult)"
		$StatusObject.BackupEnd = [datetime]::Now
		$StatusObject
	}
#endregion

	$StatusObject = New-Object psobject -Property @{
		BackupType = $Type;
		Status = 0;
		StatusMessage = [string]::Empty;
		DataBaseSize = 0;
		LogFileCount = 0;
		BackupStart = [datetime]::Now;
		BackupEnd = [datetime]::Now
	}
	if ($BackupKey) {
		if ($Password -eq $null -or $Password -eq [string]::Empty) {
			$Password = Read-Host "Enter password"
		}
		__BackupKey $Password
	}
	$ofs = ", "
	Write-Verbose "Set server name to $($Env:computername)"
	$Server = $Env:COMPUTERNAME
	$ServerStatus = $false

	Write-Verbose "Test connection to local CA"
	$hresult = [PKI.CertAdm]::CertSrvIsServerOnline($Server,[ref]$ServerStatus)
	if (!$ServerStatus) {
		$StatusObject.Status = 0x800706ba
		__status $StatusObject
		break
	}

	Write-Debug "Instantiate backup context handle"
	[IntPtr]$phbc = [IntPtr]::Zero

	Write-Debug "Retrieve backup context handle for the backup type: $type"
	$hresult = switch ($Type) {
		"Full" {[PKI.CertAdm]::CertSrvBackupPrepare($Server,0,1,[ref]$phbc)}
		"Incremental" {[PKI.CertAdm]::CertSrvBackupPrepare($Server,0,2,[ref]$phbc)}
	}
	if ($hresult -ne 0) {
		$StatusObject.Status = $hresult
		__status $StatusObject
		break
	}
	Write-Debug "Backup context handle is: $phbc"
	
	$cbBuffer = 524288
	$pvBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($cbBuffer)
	
	if ($Type -eq "Full") {
		Write-Debug "Retrieve restore map"
		$ppwszzDatabaseLocationList = [IntPtr]::Zero
		$pcbSize = 0
		$hresult = [PKI.CertAdm]::CertSrvRestoreGetDatabaseLocations($phbc,[ref]$ppwszzDatabaseLocationList,[ref]$pcbSize)
		Write-Debug "Restore map handle: $ppwszzDatabaseLocationList"
		Write-Debug "Restore map size in bytes: $pcbSize"
		$Bytes = New-Object byte[] -ArgumentList $pcbSize
		[Runtime.InteropServices.Marshal]::Copy($ppwszzDatabaseLocationList,$Bytes,0,$pcbSize)
		Write-Verbose "Writing restore map to: $BackupDir\certbkxp.dat"
		[IO.File]::WriteAllBytes("$BackupDir\certbkxp.dat",$Bytes)
		Remove-Variable Bytes -Force

		Write-Verbose "Retrieve DB file locations"
		$ppwszzAttachmentInformation = [IntPtr]::Zero
		$pcbSize = 0
		$hresult = [PKI.CertAdm]::CertSrvBackupGetDatabaseNames($phbc,[ref]$ppwszzAttachmentInformation,[ref]$pcbSize)
		Write-Debug "DB file location handle: $ppwszzAttachmentInformation"
		Write-Debug "DB file location size in bytes: $pcbSize"
		if ($hresult -ne 0) {
			$StatusObject.Status = $hresult
			__status $StatusObject
			break
		}
		if ($pcbSize -eq 0) {
			$StatusObject.Status = 0x80070012
			__status $StatusObject
			break
		}
		$Bytes = New-Object byte[] -ArgumentList $pcbSize
		[Runtime.InteropServices.Marshal]::Copy($ppwszzAttachmentInformation,$Bytes,0,$pcbSize)
		$DBPaths = Split-BackupPath $Bytes
		Write-Verbose "Unstripped DB paths:"
		$DBPaths | ForEach-Object {Write-Verbose $_}
		Remove-Variable Bytes
		# backup DB files
		# initialize read buffer
		Write-Debug "Set read buffer to: $cbBuffer bytes"
		$script:Size = 0
		foreach ($File in $DBPaths) {
			$File = $File.Substring(1,($File.Length - 1))
			Write-Verbose "Backing up file: $File"
			__BackupRoutine $phbc $File $BackupDir $pvBuffer $cbBuffer "database"
		}
		$StatusObject.DataBaseSize = $script:Size
		Remove-Variable DBPaths
	} else {
		Write-Verbose "Skipping CA database backup."
		Write-Debug "Skipping CA database backup. Logs only"
	}
	# retrieve log files
	$ppwszzBackupLogFiles = [IntPtr]::Zero
	$pcbSize = 0
	Write-Verbose "Retrieving DB log file list"
	$hresult = [PKI.CertAdm]::CertSrvBackupGetBackupLogs($phbc,[ref]$ppwszzBackupLogFiles,[ref]$pcbSize)
	Write-Debug "Log file location handle: $ppwszzAttachmentInformation"
	Write-Debug "Log file location size in bytes: $pcbSize"
	if ($hresult -ne 0) {
		$StatusObject.Status = 0x80070012
		__status $StatusObject
		break
	}
	$Bytes = New-Object byte[] -ArgumentList $pcbSize
	[Runtime.InteropServices.Marshal]::Copy($ppwszzBackupLogFiles,$Bytes,0,$pcbSize)
	$LogPaths = Split-BackupPath $Bytes
	$StatusObject.LogFileCount = $LogPaths.Length
	Write-Verbose "Unstripped LOG paths:"
	$LogPaths | ForEach-Object {Write-Verbose $_}
	Remove-Variable Bytes
	foreach ($File in $LogPaths) {
		$File = $File.Substring(1,($File.Length - 1))
		Write-Verbose "Backing up file: $File"
		__BackupRoutine $phbc $File $BackupDir $pvBuffer $cbBuffer "log"
	}
	[Runtime.InteropServices.Marshal]::FreeHGlobal($pvBuffer)
	Remove-Variable LogPaths
	Write-Debug "Releasing read buffer"
	# truncate logs
	if ($Type -eq "Full" -and !$KeepLog) {
		Write-Verbose "Truncating logs"
		Write-Debug "Truncating logs"
		$hresult = [PKI.CertAdm]::CertSrvBackupTruncateLogs($phbc)
		if ($hresult -ne 0) {
			$StatusObject.Status = 0x80070012
			__status $StatusObject
			break
		}
	}
	# retrieve and backup dynamic files
	if ($Extended) {
		$Now = Get-Date -Format dd.MM.yyyy
		Write-Verbose "Export CA configuration registry hive and CAPolicy.inf (if possible)."
		Write-Debug "Export CA configuration registry hive and CAPolicy.inf (if possible)."
		reg export "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" "$Path\CAConfig-$($Now.ToString()).reg" /y | Out-Null
		Copy-Item $Env:windir\CAPolicy.inf -Destination $Path -Force -ErrorAction SilentlyContinue
	}
	__status $StatusObject
}
# SIG # Begin signature block
# MIIT9wYJKoZIhvcNAQcCoIIT6DCCE+QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfZYSErsVgTK+sJqqPIqFXGWb
# rDGggg8tMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggaQMIIFeKADAgECAhAGnC2gXFmy7q5ox0B+K5/xMA0GCSqGSIb3DQEBBQUAMG8x
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xLjAsBgNVBAMTJURpZ2lDZXJ0IEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBLTEwHhcNMTMwMTI4MDAwMDAwWhcNMTQwMjA1MTIwMDAwWjBc
# MQswCQYDVQQGEwJMVjEKMAgGA1UECBMBLTENMAsGA1UEBxMEUmlnYTEYMBYGA1UE
# ChMPU3lzYWRtaW5zIExWIElLMRgwFgYDVQQDEw9TeXNhZG1pbnMgTFYgSUswggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChzYQDqMuYBs/jnfLsMvbbuZTV
# wwY1yHJ92TvD7bNwVx1OFEENNGrXkLNz9Ro6XtJ8zcB/80FmxE9jL2ARLd2TmEJt
# aYBvvmGMsS17zCGYDZZU7aVjaKZX2R665V+LWJUEIaHCcY5XjfmeZvCk1tHOtTAX
# qKjUd6fGIWXpxrSP9WKxW7FpTDGzQ2BpkZ+snmPS9yWDgeu709zPeoSTbdEIva6J
# ckzFj0uK7k2BqlLG3dsxBIzUqr+yTbdAuWfhR731iyWHk5GT6XCtBjBmuouKOCT1
# Jn0xmYNAwgdtSiBlTL4A/Rm3YuP57VP+EBrrgA5g7Pekdo9APU+7QqWF51YhAgMB
# AAGjggM5MIIDNTAfBgNVHSMEGDAWgBR7aM4pqsAXvkl64eU/1qf3RY81MjAdBgNV
# HQ4EFgQUgiIRdHkZ2SctPGaLDBBOX67N7NQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMHMGA1UdHwRsMGowM6AxoC+GLWh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9hc3N1cmVkLWNzLTIwMTFhLmNybDAzoDGgL4YtaHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL2Fzc3VyZWQtY3MtMjAxMWEuY3JsMIIBxAYDVR0gBIIB
# uzCCAbcwggGzBglghkgBhv1sAwEwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3
# LmRpZ2ljZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUH
# AgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQBy
# AHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBj
# AGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAg
# AEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQ
# AGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBt
# AGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBj
# AG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBl
# AHIAZQBuAGMAZQAuMIGCBggrBgEFBQcBAQR2MHQwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBMBggrBgEFBQcwAoZAaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ29kZVNpZ25pbmdDQS0xLmNy
# dDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBBQUAA4IBAQAh3nRpJ8WxlJZ8NI1y
# B4iM7RzjL7D57lVj/shWkbCp2znzBLVMGnYVK+Z0QL2PSxpxX52Khhc2MHXTM+Yf
# 74sO5XZm5IMMAnlpK2FeyQBGIKcFmrzkvj3LUcCc7RU0duioVHQ+C+hOQmpmSYiA
# 0zOoJgO4zFy5SKT1mzPEElup1B2aiE+WQZpcEWUv4I+/lYvYIBhyz+WZ2xm4kLbG
# QYR/08cei9X70x02wpgMSK9yKhSzcpwbq+ccnOtFUlTLNyRr9OuRnTi3ZCM8w5Is
# a2+UsnxsF5F5CGsw+GMRT/Jrm2mHMcKIW+qp8reUXattRTjobnbARJSQS3NBt4wp
# wTIZMYIENDCCBDACAQEwgYMwbzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEuMCwGA1UEAxMlRGln
# aUNlcnQgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EtMQIQBpwtoFxZsu6uaMdA
# fiuf8TAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAjBgkqhkiG9w0BCQQxFgQUcDuHFnL8dWOkk7XaJDiEJAeZKR4wDQYJKoZI
# hvcNAQEBBQAEggEAPQDj0EBW/L9+wsEYM2D/xlfq63gEE/8SsO4FUX8WCZiMdsFf
# L5aiIh2EzVjG014v74M29J5/FHBT/+5tY+r+eHzdteNtz6GDtO7BgyY6wTOHvSxb
# ixPTr4zJ9a4/3V8ds1YnXf7vj5PM/t6gVe2weHqRJzzgTTzpOUq5aWOc2C3mWwm0
# IPVWQiFBkULfd4S9WLnM7a0sDSu/6WUgn/2KOUtO/hoX3QgH1np7dgXo80xyAuoE
# +6SMMhUDtQOlWJtghg77ghjHN2u04dD/ZgOJptrsyLp19Du7ZfolWje0Z/f1C7pR
# fgaTWscIxXqyvX/3UD9+qbCgIa8iWxrniUngxKGCAgswggIHBgkqhkiG9w0BCQYx
# ggH4MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBD
# b3Jwb3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2
# aWNlcyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkGBSsOAwIaBQCgXTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xMzEwMjcxNDA4
# NDJaMCMGCSqGSIb3DQEJBDEWBBTk4DZ/xS+cR5DewSSHl1Jve8Q2XzANBgkqhkiG
# 9w0BAQEFAASCAQB9/wAlas6/50vYixoi37m4W0hmjPQehD/JLcg7Ojw/QoU1OofI
# aGZtCrt9UbFczKCj8lhYoiFg1raUxJ/4v4w8bIbBKLiI2SCYrAXQiWnSVfy4/YUD
# lOXKvckLsrXg8EdUuc2nW0IaO1BHU5x7Rs/vgBlvYazEd+dPvlL3MTaTpfVsNkFV
# z5vCQwNnTOaEphoefoP+yiwlDsw1IJMgGKovISWYbHoLhsbHTMrFh+ip49VnGfkL
# ejHQYOMQv47F0oaMg1es67GtwmvmrXS4Ys+sXv2YpHfaFkRSANtNaOMQvHLQSp54
# NfKNVIF7RCewXO6X9ikhjFDvDHBpIgrvnxdi
# SIG # End signature block
