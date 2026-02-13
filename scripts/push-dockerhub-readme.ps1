# Push README to Docker Hub via REST API
# Usage: .\scripts\push-dockerhub-readme.ps1
# Requires: Docker Hub username and password/PAT

param(
    [string]$Username = "qandil",
    [string]$Repository = "qandil/waftester"
)

$ErrorActionPreference = "Stop"

# Read README from file
$readmePath = Join-Path $PSScriptRoot ".." "DOCKERHUB_README.md"
if (-not (Test-Path $readmePath)) {
    Write-Error "README file not found at $readmePath"
    exit 1
}
$readme = Get-Content -Path $readmePath -Raw

# Get credentials
$password = Read-Host "Enter Docker Hub password or PAT for $Username" -AsSecureString
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
)

# Login to get JWT token
Write-Host "Logging in to Docker Hub..." -ForegroundColor Cyan
$loginBody = @{ username = $Username; password = $plainPassword } | ConvertTo-Json
try {
    $loginResp = Invoke-RestMethod -Uri "https://hub.docker.com/v2/users/login/" `
        -Method Post -Body $loginBody -ContentType "application/json"
    $token = $loginResp.token
    Write-Host "Login successful." -ForegroundColor Green
} catch {
    Write-Error "Login failed: $_"
    exit 1
}

# Update repository description
Write-Host "Updating repository description..." -ForegroundColor Cyan
$patchBody = @{ full_description = $readme } | ConvertTo-Json -Depth 10
try {
    $resp = Invoke-RestMethod -Uri "https://hub.docker.com/v2/repositories/$Repository/" `
        -Method Patch -Body $patchBody -ContentType "application/json" `
        -Headers @{ Authorization = "JWT $token" }
    Write-Host "README updated successfully!" -ForegroundColor Green
    Write-Host "View at: https://hub.docker.com/r/$Repository" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to update README: $_"
    exit 1
}
