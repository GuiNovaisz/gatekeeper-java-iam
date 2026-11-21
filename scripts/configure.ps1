param([string]$BootstrapLogin='operator@example.test')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(Test-Path -LiteralPath (Join-Path $root '.env')) { throw '.env already exists; preserve the existing key material.' }
function New-Secret([int]$Count=32) {
    $bytes=[byte[]]::new($Count)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    [Convert]::ToBase64String($bytes)
}
$database=New-Secret
$mfaKey=New-Secret
$storePassword=New-Secret
$clientSecret=New-Secret
$bootstrapPassword=New-Secret
$keytool=Join-Path $env:JAVA_HOME 'bin\keytool.exe'
if(!(Test-Path -LiteralPath $keytool)) { throw 'JAVA_HOME must point to a JDK 21+.' }
$secretDirectory=Join-Path $root 'secrets'
New-Item -ItemType Directory -Path $secretDirectory -Force | Out-Null
$store=Join-Path $secretDirectory 'signing.p12'
if(Test-Path -LiteralPath $store) {throw 'Signing store already exists; refusing to overwrite.'}
$env:GK_STORE_PASSWORD=$storePassword
try {
    & $keytool -genkeypair -alias signing -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -validity 365 -dname 'CN=Gatekeeper local' -storetype PKCS12 -keystore $store -storepass:env GK_STORE_PASSWORD 2>$null
    if($LASTEXITCODE -ne 0){throw 'Key generation failed'}
}finally{Remove-Item Env:GK_STORE_PASSWORD}
$lines=@("DATABASE_PASSWORD=$database","MFA_ENCRYPTION_KEY=$mfaKey","SIGNING_KEYSTORE_PASSWORD=$storePassword","DEMO_CLIENT_SECRET=$clientSecret","BOOTSTRAP_LOGIN=$BootstrapLogin","BOOTSTRAP_PASSWORD=$bootstrapPassword")
[IO.File]::WriteAllLines((Join-Path $root '.env'),$lines,[Text.UTF8Encoding]::new($false))
# Restrict local credentials to the current Windows user (Docker Desktop reads through that user).
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls (Join-Path $root '.env') /inheritance:r /grant:r "${user}:(F)" | Out-Null
& icacls $secretDirectory /inheritance:r /grant:r "${user}:(OI)(CI)(F)" | Out-Null
Write-Output 'Local configuration generated. Secrets are in ignored .env and secrets/. Do not publish them.'
