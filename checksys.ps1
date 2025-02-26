# CheckSystem - Herramienta de Análisis de Seguridad para Windows
# by MXR

# Función para escanear archivos .exe
function Scan-ExeFiles {
    Write-Host "=== Archivos .exe ===" -ForegroundColor Red
    $exeFiles = Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue
    if ($exeFiles.Count -eq 0) {
        Write-Host "No se encontraron archivos ejecutables anómalos."
    } else {
        $exeFiles | ForEach-Object { Write-Host $_.FullName }
    }
}

# Función para analizar procesos con VirusTotal
function Scan-VirusTotal {
    param ([string]$apiKey)
    
    $processes = Get-Process | Select-Object -ExpandProperty ProcessName -Unique
    
    foreach ($process in $processes) {
        Write-Host "Analizando: $process..." -ForegroundColor Yellow
        $hash = (Get-FileHash "C:\Windows\System32\$process.exe" -ErrorAction SilentlyContinue).Hash
        if ($hash) {
            $url = "https://www.virustotal.com/api/v3/files/$hash"
            $headers = @{ "x-apikey" = $apiKey }
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction SilentlyContinue
            Write-Host "Resultado: $($response.data.attributes.last_analysis_stats)" -ForegroundColor Green
        }
    }
}

# Función para escanear tareas programadas sospechosas
function Scan-ScheduledTasks {
    Write-Host "=== Tareas Programadas ===" -ForegroundColor Cyan
    Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | Format-Table TaskName, State, Actions -AutoSize
}

# Función para escanear puertos abiertos
function Scan-OpenPorts {
    Write-Host "=== Puertos Abiertos ===" -ForegroundColor Cyan
    netstat -ano | Select-String "LISTENING" | ForEach-Object { Write-Host $_ }
}

# Función para buscar archivos sospechosos
function Scan-SuspiciousFiles {
    Write-Host "=== Archivos Ocultos y Recientes ===" -ForegroundColor Cyan
    Get-ChildItem -Path C:\ -Recurse -Force | Where-Object { $_.Attributes -match "Hidden" -or $_.LastWriteTime -gt (Get-Date).AddDays(-5) } | Format-Table FullName, LastWriteTime, Attributes -AutoSize
}

# Bucle principal
while ($true) {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Red
    Write-Host "===*****    CHECK SYSTEM     *****===" -ForegroundColor Red
    Write-Host "====================================" -ForegroundColor Red
    Write-Host "1. Consumo de recursos" -ForegroundColor Magenta
    Write-Host "2. Conexiones de red" -ForegroundColor Magenta
    Write-Host "3. Procesos inusuales" -ForegroundColor Magenta
    Write-Host "4. Escaneo de archivos .exe" -ForegroundColor Magenta
    Write-Host "5. Análisis con VirusTotal" -ForegroundColor Magenta
    Write-Host "6. Tareas programadas sospechosas" -ForegroundColor Magenta
    Write-Host "7. Escaneo de puertos abiertos" -ForegroundColor Magenta
    Write-Host "8. Archivos ocultos recientes" -ForegroundColor Magenta
    Write-Host "9. Salir" -ForegroundColor Magenta
    
    $option = Read-Host "Ingrese el número de opción deseado"
    
    switch ($option) {
        1 { Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize }
        2 { Get-NetTCPConnection | Format-Table -AutoSize }
        3 { Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize }
        4 { Scan-ExeFiles }
        5 {
            $apiKey = Read-Host "Ingrese su API Key de VirusTotal"
            Scan-VirusTotal -apiKey $apiKey
        }
        6 { Scan-ScheduledTasks }
        7 { Scan-OpenPorts }
        8 { Scan-SuspiciousFiles }
        9 { Write-Host "Cerrando el programa..."; exit }
        default { Write-Host "Opción no válida." -ForegroundColor Red }
    }
    
    Start-Sleep -Seconds 3
}
