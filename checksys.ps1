# Checksys Profesional - Herramienta de Análisis para Windows

# Solicitar API Key para VirusTotal
$global:VT_API_Key = Read-Host "Ingrese su API Key de VirusTotal"

# Función para guardar resultados
function Guardar-Resultados {
    param(
        [string]$contenido
    )
    $respuesta = Read-Host "¿Desea guardar los resultados? (S/N)"
    if ($respuesta -match "^[Ss]$") {
        $ruta = Read-Host "Ingrese la ruta y nombre del archivo para guardar" 
        $contenido | Out-File -FilePath $ruta -Encoding utf8
        Write-Host "Resultados guardados en $ruta" -ForegroundColor Green
    }
}

# Función para escanear archivos .exe
function Scan-ExeFiles {
    Write-Host "=== Archivos .exe ===" -ForegroundColor Red
    $exeFiles = Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue
    if ($exeFiles.Count -eq 0) {
        Write-Host "No se encontraron archivos ejecutables anómalos."
    } else {
        $resultados = $exeFiles | ForEach-Object { $_.FullName }
        Write-Host $resultados
        Guardar-Resultados -contenido $resultados
    }
}

# Función para analizar procesos con VirusTotal
function Scan-VirusTotal {
    $procesos = Get-Process | Select-Object ProcessName, Id, Path -ErrorAction SilentlyContinue
    foreach ($proceso in $procesos) {
        if ($proceso.Path) {
            $hash = (Get-FileHash $proceso.Path -Algorithm SHA256).Hash
            $url = "https://www.virustotal.com/api/v3/files/$hash"
            $headers = @{ "x-apikey" = $global:VT_API_Key }
            try {
                $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
                Write-Host "Proceso: $($proceso.ProcessName) - Detección: $($response.data.attributes.last_analysis_stats.malicious) detecciones" -ForegroundColor Yellow
            } catch {
                Write-Host "Error al consultar VirusTotal para $($proceso.ProcessName)" -ForegroundColor Red
            }
        }
    }
}

# Función para escanear tareas programadas sospechosas
function Scan-ScheduledTasks {
    Write-Host "=== Tareas Programadas ===" -ForegroundColor Cyan
    $tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notmatch "Microsoft" }
    if ($tasks.Count -eq 0) {
        Write-Host "No se encontraron tareas sospechosas."
    } else {
        $resultados = $tasks | Format-Table -AutoSize | Out-String
        Write-Host $resultados
        Guardar-Resultados -contenido $resultados
    }
}

# Función para escanear puertos abiertos
function Scan-OpenPorts {
    Write-Host "=== Puertos Abiertos ===" -ForegroundColor Cyan
    $resultados = netstat -ano | Out-String
    Write-Host $resultados
    Guardar-Resultados -contenido $resultados
}

# Función para buscar archivos sospechosos
function Scan-SuspiciousFiles {
    Write-Host "=== Archivos Sospechosos ===" -ForegroundColor Cyan
    $resultados = Get-ChildItem -Path C:\ -Recurse -Hidden -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Format-Table -AutoSize | Out-String
    Write-Host $resultados
    Guardar-Resultados -contenido $resultados
}

# Bucle principal
while ($true) {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Red
    Write-Host "===******    CHECK OF SYSTEM    ******===" -ForegroundColor Red
    Write-Host "====================================" -ForegroundColor Red
    Write-Host "1. Consumo de recursos" -ForegroundColor Magenta
    Write-Host "2. Conexiones de red" -ForegroundColor Magenta
    Write-Host "3. Procesos inusuales" -ForegroundColor Magenta
    Write-Host "4. Archivos .exe" -ForegroundColor Magenta
    Write-Host "5. Analizar procesos con VirusTotal" -ForegroundColor Magenta
    Write-Host "6. Escaneo de tareas programadas" -ForegroundColor Magenta
    Write-Host "7. Escaneo de puertos abiertos" -ForegroundColor Magenta
    Write-Host "8. Archivos sospechosos" -ForegroundColor Magenta
    Write-Host "9. Salir" -ForegroundColor Magenta

    $option = Read-Host "Ingrese el número de opción deseado"
    
    switch ($option) {
        1 { Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize | Out-String | Tee-Object -Variable resultados; Write-Host $resultados; Guardar-Resultados -contenido $resultados }
        2 { Get-NetTCPConnection | Format-Table -AutoSize | Out-String | Tee-Object -Variable resultados; Write-Host $resultados; Guardar-Resultados -contenido $resultados }
        3 { Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize | Out-String | Tee-Object -Variable resultados; Write-Host $resultados; Guardar-Resultados -contenido $resultados }
        4 { Scan-ExeFiles }
        5 { Scan-VirusTotal }
        6 { Scan-ScheduledTasks }
        7 { Scan-OpenPorts }
        8 { Scan-SuspiciousFiles }
        9 { Write-Host "Cerrando el programa..."; exit }
        default { Write-Host "Opción no válida." -ForegroundColor Red }
    }
    
    Read-Host "Presione Enter para volver al menú principal"
}

