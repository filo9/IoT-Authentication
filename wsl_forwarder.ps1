$wslPort = 9999
$wifiPort = 9999
if ($null -ne $client) { $client.Close() }
$client = New-Object System.Net.Sockets.UdpClient $wslPort
$target = New-Object System.Net.Sockets.UdpClient
$target.EnableBroadcast = $true
$dest = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast, $wifiPort)

Write-Host "🚀 WSL 广播中继已启动... [WSL -> Windows -> WiFi]" -ForegroundColor Cyan
Write-Host "📡 正在转发..." -ForegroundColor Gray

try {
    while($true) {
        $receive = $client.Receive([ref](New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)))
        $target.Send($receive, $receive.Length, $dest)
        $msg = [System.Text.Encoding]::UTF8.GetString($receive)
        Write-Host "✅ [$(Get-Date -Format 'HH:mm:ss')] 已中继暗号: $msg" -ForegroundColor Green
    }
} finally {
    $client.Close(); $target.Close()
}