<#
.SYNOPSIS
    Generates a Windows ICO file from the macOS source PNG artwork.

.DESCRIPTION
    This script reads apps/macos/Artwork/icon-1024.png and resizes it to
    multiple dimensions (16, 20, 24, 32, 40, 48, 64, 256 pixels), then
    writes a valid ICO file containing PNG-compressed entries for each size.

    The ICO format is constructed manually:
    - ICONDIR header (6 bytes): reserved, type (1=icon), image count
    - ICONDIRENTRY array (16 bytes per entry): size, offset, etc.
    - PNG image data payloads

.PARAMETER SourceImage
    Path to the source PNG image (default: apps/macos/Artwork/icon-1024.png)

.PARAMETER OutputFile
    Path to write the ICO file (default: apps/windows/Kagisecure.App/Assets/Kagisecure.ico)
#>

param(
    [string]$SourceImage = "apps/macos/Artwork/icon-1024.png",
    [string]$OutputFile = "apps/windows/Kagisecure.App/Assets/Kagisecure.ico"
)

Add-Type -AssemblyName System.Drawing

# Ensure output directory exists
$OutputDir = Split-Path -Parent $OutputFile
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force $OutputDir | Out-Null
}

# Load the source image - get absolute path
Write-Host "Loading source image: $SourceImage"
if (-not (Test-Path $SourceImage)) {
    Write-Error "Source image not found: $SourceImage"
    exit 1
}
$absolutePath = (Get-Item $SourceImage).FullName
$sourceImage = [System.Drawing.Image]::FromFile($absolutePath)
Write-Host "Source image size: $($sourceImage.Width)x$($sourceImage.Height)"

# Define icon sizes
$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$pngData = @()

# Resize and convert each size to PNG
Write-Host "Resizing images..."
foreach ($size in $sizes) {
    Write-Host "  Creating $size x $size..."

    # Create resized bitmap with high quality
    $resized = New-Object System.Drawing.Bitmap($size, $size)
    $graphics = [System.Drawing.Graphics]::FromImage($resized)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

    # Draw source image scaled to target size
    $graphics.DrawImage($sourceImage, 0, 0, $size, $size)
    $graphics.Dispose()

    # Save as PNG to memory stream
    $stream = New-Object System.IO.MemoryStream
    $resized.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngData += @{Size = $size; Data = $stream.ToArray()}
    $stream.Dispose()
    $resized.Dispose()
}

$sourceImage.Dispose()

# Build ICO file
Write-Host "Building ICO file..."
$icoStream = New-Object System.IO.MemoryStream

# Write ICONDIR header (6 bytes)
# Bytes 0-1: Reserved (0)
$icoStream.WriteByte(0)
$icoStream.WriteByte(0)
# Bytes 2-3: Type (1 = icon)
$icoStream.WriteByte(1)
$icoStream.WriteByte(0)
# Bytes 4-5: Count of images
$icoStream.WriteByte($pngData.Count)
$icoStream.WriteByte(0)

# Calculate offset where image data starts
# Header is 6 bytes + (16 bytes per entry)
$imageDataOffset = 6 + ($pngData.Count * 16)

# Write ICONDIRENTRY for each image
$currentOffset = $imageDataOffset
foreach ($entry in $pngData) {
    $data = $entry.Data
    $dataSize = $data.Length
    $size = $entry.Size

    # Width (1 byte) - 0 means 256
    if ($size -eq 256) {
        $icoStream.WriteByte(0)
    } else {
        $icoStream.WriteByte($size)
    }

    # Height (1 byte) - 0 means 256
    if ($size -eq 256) {
        $icoStream.WriteByte(0)
    } else {
        $icoStream.WriteByte($size)
    }

    # Color count (1 byte) - 0 for > 256 colors
    $icoStream.WriteByte(0)

    # Reserved (1 byte)
    $icoStream.WriteByte(0)

    # Color planes (2 bytes, little-endian)
    $icoStream.WriteByte(1)
    $icoStream.WriteByte(0)

    # Bits per pixel (2 bytes, little-endian) - 32 for RGBA PNG
    $icoStream.WriteByte(32)
    $icoStream.WriteByte(0)

    # Size of image data (4 bytes, little-endian)
    $sizeBytes = [System.BitConverter]::GetBytes([uint32]$dataSize)
    $icoStream.Write($sizeBytes, 0, 4)

    # Offset of image data (4 bytes, little-endian)
    $offsetBytes = [System.BitConverter]::GetBytes([uint32]$currentOffset)
    $icoStream.Write($offsetBytes, 0, 4)

    $currentOffset += $dataSize
}

# Write PNG data for each image
foreach ($entry in $pngData) {
    $data = $entry.Data
    $icoStream.Write($data, 0, $data.Length)
}

# Write to file
$icoStream.Position = 0
$fileStream = New-Object System.IO.FileStream($OutputFile, [System.IO.FileMode]::Create)
$icoStream.CopyTo($fileStream)
$fileStream.Close()
$icoStream.Close()

Write-Host "ICO file created successfully: $OutputFile"
Write-Host "Included sizes: $($sizes -join ', ')"
