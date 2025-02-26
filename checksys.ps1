# Función para escanear archivos .exe
def Scan-ExeFiles {
    Write-Host "=== Archivos .exe ===" -ForegroundColor Red
    $exeFiles = Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue
    if ($exeFiles.Count -eq 0) {
        Write-Host "No se encontraron archivos ejecutables anómalos."
    } else {
        $exeFiles | ForEach-Object { Write-Host $_.FullName }
    }
}

# Bucle principal
while ($true) {
    Clear-Host
    Write-Host "====================================" -ForegroundColor Red
    Write-Host "===******                  ******===" -ForegroundColor Red
    Write-Host "===*****     C H E C K      *****===" -ForegroundColor Red
    Write-Host "===*****        O F         *****===" -ForegroundColor Red
    Write-Host "===*****     S Y S T E M    *****===" -ForegroundColor Red
    Write-Host "===*****                    *****===" -ForegroundColor Red
    Write-Host "===******       by:mxr     ******===" -ForegroundColor Red
    Write-Host "====================================" -ForegroundColor Red
    Write-Host "1. Consumo de recursos" -ForegroundColor Magenta
    Write-Host "2. Conexiones de red" -ForegroundColor Magenta
    Write-Host "3. Procesos inusuales" -ForegroundColor Magenta
    Write-Host "4. Archivos .exe" -ForegroundColor Magenta
    Write-Host "5. Salir" -ForegroundColor Magenta
    
    $option = Read-Host "Ingrese el número de opción deseado"
    
    switch ($option) {
        1 {
            Write-Host "=== Consumo de recursos ===" -ForegroundColor Cyan
            Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize
        }
        2 {
            Write-Host "=== Conexiones de red ===" -ForegroundColor Cyan
            Get-NetTCPConnection | Format-Table -AutoSize
        }
        3 {
            Write-Host "=== Procesos inusuales ===" -ForegroundColor Cyan
            Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize
        }
        4 { Scan-ExeFiles }
        5 {
            Write-Host "Cerrando el programa..."
            exit
        }
        default {
            Write-Host "Opción no válida." -ForegroundColor Red
        }
    }
    
    Start-Sleep -Seconds 3
}
