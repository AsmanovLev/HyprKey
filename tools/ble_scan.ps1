[Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher, Windows.Devices.Bluetooth, ContentType = WindowsRuntime] > $null

$watcher = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher]::new()
$watcher.ScanningMode = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode]::Active

$action = {
    $adv = $EventArgs
    $name = $adv.Advertisement.LocalName
    $addr = $adv.BluetoothAddress.ToString("X12")
    $rssi = $adv.RawSignalStrengthInDBm
    $uuids = ($adv.Advertisement.ServiceUuids | ForEach-Object { $_.ToString() }) -join ", "
    Write-Host ("BLE Adv: [{0}] RSSI={1} Name='{2}' UUIDs='{3}'" -f $addr, $rssi, $name, $uuids)
}

$job = Register-ObjectEvent -InputObject $watcher -EventName Received -Action $action
$watcher.Start()
Write-Host "Scanning for 4 seconds..."
Start-Sleep -Seconds 4
$watcher.Stop()
Unregister-Event -SourceIdentifier $job.Name
Remove-Job $job
