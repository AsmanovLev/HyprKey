$ErrorActionPreference = "Stop"

$SDK = "C:\Users\User\AppData\Local\Android\Sdk"
$BT = "$SDK\build-tools\34.0.0"
$PLAT = "$SDK\platforms\android-34\android.jar"
$JDK = "C:\Program Files\Microsoft\jdk-21.0.10.7-hotspot\bin"

$AAPT2 = "$BT\aapt2.exe"
$D8 = "$BT\d8.bat"
$ZIPALIGN = "$BT\zipalign.exe"
$APKSIGNER = "$BT\apksigner.bat"
$JAVAC = "$JDK\javac.exe"
$JAR = "$JDK\jar.exe"
$KEYTOOL = "$JDK\keytool.exe"

Set-Location "S:\hyprkey\tools\HyprNfcDebug"

# Cleanup
Remove-Item -Recurse -Force bin, obj, res.zip, *.apk -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path bin, obj | Out-Null

Write-Host ">>> Step 1: Compiling resources with aapt2..."
& $AAPT2 compile --dir res -o res.zip

Write-Host ">>> Step 2: Linking resources with aapt2..."
& $AAPT2 link -I $PLAT -o unaligned.apk res.zip --manifest AndroidManifest.xml --java src --auto-add-overlay --min-sdk-version 24 --target-sdk-version 34

Write-Host ">>> Step 3: Compiling Java sources..."
$javaFiles = Get-ChildItem -Recurse src -Filter "*.java" | ForEach-Object { $_.FullName }
& $JAVAC -source 1.8 -target 1.8 -cp $PLAT -d bin $javaFiles

Write-Host ">>> Step 4: Converting bytecode to DEX with d8..."
$classFiles = Get-ChildItem -Recurse bin -Filter "*.class" | ForEach-Object { $_.FullName }
& $D8 $classFiles --output bin --lib $PLAT

Write-Host ">>> Step 5: Packaging classes.dex into APK..."
& $JAR uf unaligned.apk -C bin classes.dex

Write-Host ">>> Step 6: Aligning APK with zipalign..."
& $ZIPALIGN -f -p 4 unaligned.apk aligned.apk

Write-Host ">>> Step 7: Signing APK..."
if (-not (Test-Path debug.keystore)) {
    & $KEYTOOL -genkeypair -keystore debug.keystore -storepass android -keypass android -alias androiddebugkey -dname "CN=Android Debug,O=Android,C=US" -keyalg RSA -keysize 2048 -validity 10000
}
& $APKSIGNER sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out HyprNfcDebug.apk aligned.apk

Write-Host ">>> Build successful: HyprNfcDebug.apk generated!"
