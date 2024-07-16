# Function to generate RSA keys and save them
function Generate-RSAKeys {
    # Create RSA object
    $RSA = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)

    # Export private key
    $privateKeyXml = $RSA.ToXmlString($true)
    $privateKeyPath = "private_key.xml"
    $privateKeyXml | Out-File -FilePath $privateKeyPath

    Write-Host "RSA keys generated and saved to $privateKeyPath."
}

# Function to sign a script using RSA key
function Sign-Script {
    param (
        [string]$scriptPath
    )

    # Load private key
    $privateKeyXml = Get-Content -Path "private_key.xml" -Raw
    if ([string]::IsNullOrWhiteSpace($privateKeyXml)) {
        Write-Error "Private key file is empty or not found."
        exit
    }

    $RSA = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
    $RSA.FromXmlString($privateKeyXml)

    # Read script content
    $scriptContent = Get-Content -Raw -Path $scriptPath

    # Concatenate script content with laptop name
    $dataToSign = [System.Text.Encoding]::UTF8.GetBytes($scriptContent + $env:COMPUTERNAME)

    try {
        # Compute the hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha256.ComputeHash($dataToSign)

        # Sign the hash
        $signature = $RSA.SignHash($hash, [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256"))

        # Save the signature
        $signaturePath = "$scriptPath.signature"
        [System.IO.File]::WriteAllBytes($signaturePath, $signature)
        Write-Host "Signature saved to $signaturePath"

        # Save the computer name to a separate file
        $computerNamePath = "$scriptPath.computername"
        $env:COMPUTERNAME | Out-File -FilePath $computerNamePath -NoNewline
        Write-Host "Computer name saved to $computerNamePath"

        # Output the thumbprint of the public key
        $publicKeyXml = $RSA.ToXmlString($false)
        $publicKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($publicKeyXml)
        $thumbprint = $sha256.ComputeHash($publicKeyBytes)
        $thumbprintHex = -join ($thumbprint | ForEach-Object { $_.ToString("x2") })
        Write-Host "Thumbprint of the public key: $thumbprintHex"

    } catch {
        Write-Error "Error occurred during signing process: $_"
    }
}

# Function to verify script signature using public key
function Verify-Script {
    param (
        [string]$scriptPath
    )

    # Load private key
    $privateKeyXml = Get-Content -Path "private_key.xml" -Raw
    if ([string]::IsNullOrWhiteSpace($privateKeyXml)) {
        Write-Error "Private key file is empty or not found."
        exit
    }

    $RSA = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
    $RSA.FromXmlString($privateKeyXml)

    # Read script content and signature
    $scriptContent = Get-Content -Raw -Path $scriptPath
    $signaturePath = "$scriptPath.signature"
    $computerNamePath = "$scriptPath.computername"

    if (-not (Test-Path $signaturePath)) {
        Write-Error "Signature file '$signaturePath' not found."
        exit
    }

    if (-not (Test-Path $computerNamePath)) {
        Write-Error "Computer name file '$computerNamePath' not found."
        exit
    }

    $signature = [System.IO.File]::ReadAllBytes($signaturePath)
    $savedComputerName = (Get-Content -Path $computerNamePath -Raw).Trim()

    # Enhanced logging for debugging
    Write-Host "Current computer name: $($env:COMPUTERNAME)"
    Write-Host "Saved computer name: $savedComputerName"

    # Compare byte representations of the computer names
    $currentComputerNameBytes = [System.Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME)
    $savedComputerNameBytes = [System.Text.Encoding]::UTF8.GetBytes($savedComputerName)

    Write-Host "Current computer name bytes: $($currentComputerNameBytes -join ', ')"
    Write-Host "Saved computer name bytes: $($savedComputerNameBytes -join ', ')"

    # Check if the script is being executed on the same machine it was signed on
    if ($env:COMPUTERNAME -ne $savedComputerName) {
        Write-Error "Script cannot be executed on this machine. It was signed for $savedComputerName."
        exit
    }

    # Concatenate script content with laptop name for verification
    $dataToVerify = [System.Text.Encoding]::UTF8.GetBytes($scriptContent + $env:COMPUTERNAME)

    try {
        # Compute the hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha256.ComputeHash($dataToVerify)

        # Verify the signature
        $verificationResult = $RSA.VerifyHash($hash, [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256"), $signature)

        if ($verificationResult) {
            Write-Output "Verification successful, script is authentic and authorized to run on this device."
        } else {
            Write-Output "Verification failed."
        }
    } catch {
        Write-Error "Verification process encountered an error: $_"
    }
}

# Check if private key exists, generate if not
if (-not (Test-Path "private_key.xml")) {
    Write-Host "Generating RSA keys..."
    Generate-RSAKeys
}

# Prompt user for script path
$scriptPath = Read-Host "Enter the path of the script to sign"

# Sign the script
Sign-Script -scriptPath $scriptPath

# Prompt for verification
$verify = Read-Host "Do you want to verify the script? (yes/no)"
if ($verify -eq "yes") {
    Verify-Script -scriptPath $scriptPath
}

