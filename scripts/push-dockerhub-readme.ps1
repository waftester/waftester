# Push DOCKERHUB_README.md to Docker Hub via REST API.
#
# Retrieves credentials from docker-credential-desktop (no manual input).
# Uses the /v2/auth/token endpoint (the old /v2/users/login is deprecated).
#
# Usage: .\scripts\push-dockerhub-readme.ps1
# Prerequisites: Docker Desktop logged in (`docker login`)

param(
    [string]$Repository = "qandil/waftester"
)

$ErrorActionPreference = "Stop"

# Read README
$readmePath = Join-Path $PSScriptRoot ".." "DOCKERHUB_README.md"
if (-not (Test-Path $readmePath)) {
    Write-Error "README not found at $readmePath"
    exit 1
}
$readme = Get-Content -Path $readmePath -Raw
Write-Host "README: $($readme.Length) chars from $readmePath" -ForegroundColor Cyan

# Get credentials from Docker credential store
Write-Host "Retrieving credentials from docker-credential-desktop..." -ForegroundColor Cyan
try {
    $creds = "https://index.docker.io/v1/" | docker-credential-desktop get 2>$null | ConvertFrom-Json
    if (-not $creds.Username -or -not $creds.Secret) {
        Write-Error "No credentials found. Run 'docker login' first."
        exit 1
    }
    Write-Host "Credentials found for user: $($creds.Username)" -ForegroundColor Green
} catch {
    Write-Error "Failed to retrieve Docker credentials: $_"
    exit 1
}

# Exchange PAT for bearer token via /v2/auth/token
Write-Host "Authenticating with Docker Hub..." -ForegroundColor Cyan
$authBody = @{ identifier = $creds.Username; secret = $creds.Secret } | ConvertTo-Json
try {
    $authResp = Invoke-RestMethod -Uri "https://hub.docker.com/v2/auth/token" `
        -Method Post -Body $authBody -ContentType "application/json"
    $token = $authResp.access_token
    Write-Host "Authentication successful." -ForegroundColor Green
} catch {
    Write-Error "Authentication failed: $_"
    exit 1
}

# Push README to repository
Write-Host "Pushing README to $Repository..." -ForegroundColor Cyan
$patchBody = @{ full_description = $readme } | ConvertTo-Json -Depth 10
try {
    $resp = Invoke-RestMethod -Uri "https://hub.docker.com/v2/repositories/$Repository/" `
        -Method Patch -Body $patchBody -ContentType "application/json" `
        -Headers @{ Authorization = "Bearer $token" }
    Write-Host "README pushed successfully ($($readme.Length) chars)." -ForegroundColor Green
    Write-Host "View at: https://hub.docker.com/r/$Repository" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to push README: $_"
    exit 1
}
