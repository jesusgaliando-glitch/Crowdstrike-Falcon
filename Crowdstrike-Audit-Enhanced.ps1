<#
.SYNOPSIS
    Script mejorado de auditoría de CrowdStrike Falcon Sensor en dominio Active Directory

.DESCRIPTION
    Escanea todos los equipos del dominio para verificar la instalación del agente CrowdStrike,
    genera reportes detallados en múltiples formatos, incluye reintentos automáticos,
    procesamiento paralelo y logging completo.

.PARAMETER OutputPath
    Ruta donde se guardarán los reportes (por defecto: directorio actual)

.PARAMETER MaxThreads
    Número máximo de hilos paralelos para el escaneo (por defecto: 10)

.PARAMETER RetryAttempts
    Número de intentos de conexión por equipo (por defecto: 2)

.PARAMETER Timeout
    Tiempo de espera en segundos para cada ping (por defecto: 2)

.EXAMPLE
    .\Crowdstrike-Audit-Enhanced.ps1

.EXAMPLE
    .\Crowdstrike-Audit-Enhanced.ps1 -OutputPath "C:\Reports" -MaxThreads 20
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [int]$MaxThreads = 10,
    [int]$RetryAttempts = 2,
    [int]$Timeout = 2
)

#region Funciones

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    $color = switch ($Level) {
        "INFO"    { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }

    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Test-CrowdStrikeInstallation {
    param(
        [string]$ComputerName
    )

    $result = [PSCustomObject]@{
        Computer = $ComputerName
        Status = "Unknown"
        ServiceStatus = $null
        ServiceStartType = $null
        Version = $null
        InstallPath = $null
        LastChecked = Get-Date
        ResponseTime = $null
    }

    $pingStart = Get-Date

    # Verificar conectividad con múltiples intentos
    $isOnline = $false
    for ($i = 1; $i -le $script:RetryAttempts; $i++) {
        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -TimeoutSeconds $script:Timeout) {
            $isOnline = $true
            break
        }
        if ($i -lt $script:RetryAttempts) {
            Start-Sleep -Milliseconds 500
        }
    }

    $result.ResponseTime = ((Get-Date) - $pingStart).TotalMilliseconds

    if (-not $isOnline) {
        $result.Status = "Offline"
        return $result
    }

    try {
        # Verificar servicio CrowdStrike
        $service = Get-Service -ComputerName $ComputerName -Name "CSFalconService" -ErrorAction Stop

        $result.ServiceStatus = $service.Status.ToString()
        $result.ServiceStartType = $service.StartType.ToString()

        # Intentar obtener información adicional del registro remoto
        try {
            $regPath = "SOFTWARE\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default"
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $key = $reg.OpenSubKey($regPath)

            if ($key) {
                $result.Version = $key.GetValue("Version")
                $result.InstallPath = $key.GetValue("InstallPath")
                $key.Close()
            }
            $reg.Close()
        } catch {
            # No es crítico si no podemos obtener la info del registro
        }

        if ($service.Status -eq "Running") {
            $result.Status = "Installed and Running"
        } else {
            $result.Status = "Installed but Not Running"
        }

    } catch {
        $result.Status = "Not Installed"
    }

    return $result
}

function Export-Reports {
    param(
        [array]$Results
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Reporte CSV completo
    $csvPath = Join-Path $script:OutputPath "CrowdStrike_Audit_Full_$timestamp.csv"
    $Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Reporte CSV completo: $csvPath" "SUCCESS"

    # Reporte HTML
    $htmlPath = Join-Path $script:OutputPath "CrowdStrike_Audit_Report_$timestamp.html"
    $htmlContent = Generate-HTMLReport -Results $Results
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log "Reporte HTML: $htmlPath" "SUCCESS"

    # Reportes por categoría
    $installed = $Results | Where-Object { $_.Status -like "*Installed*" }
    $notInstalled = $Results | Where-Object { $_.Status -eq "Not Installed" }
    $offline = $Results | Where-Object { $_.Status -eq "Offline" }

    if ($notInstalled.Count -gt 0) {
        $missingPath = Join-Path $script:OutputPath "CrowdStrike_Missing_$timestamp.csv"
        $notInstalled | Export-Csv -Path $missingPath -NoTypeInformation -Encoding UTF8
        Write-Log "Equipos sin CrowdStrike: $missingPath" "WARNING"
    }

    if ($offline.Count -gt 0) {
        $offlinePath = Join-Path $script:OutputPath "CrowdStrike_Offline_$timestamp.csv"
        $offline | Export-Csv -Path $offlinePath -NoTypeInformation -Encoding UTF8
        Write-Log "Equipos offline: $offlinePath" "WARNING"
    }
}

function Generate-HTMLReport {
    param([array]$Results)

    $installed = ($Results | Where-Object { $_.Status -like "*Installed*" }).Count
    $notInstalled = ($Results | Where-Object { $_.Status -eq "Not Installed" }).Count
    $offline = ($Results | Where-Object { $_.Status -eq "Offline" }).Count
    $total = $Results.Count

    $installedPercent = if ($total -gt 0) { [math]::Round(($installed / $total) * 100, 2) } else { 0 }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reporte de Auditoría CrowdStrike</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #e01f27; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-box { padding: 20px; border-radius: 6px; text-align: center; }
        .stat-box.installed { background: #d4edda; border-left: 4px solid #28a745; }
        .stat-box.missing { background: #f8d7da; border-left: 4px solid #dc3545; }
        .stat-box.offline { background: #fff3cd; border-left: 4px solid #ffc107; }
        .stat-box.total { background: #d1ecf1; border-left: 4px solid #17a2b8; }
        .stat-number { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .stat-label { font-size: 14px; color: #666; text-transform: uppercase; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #e01f27; color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f9f9f9; }
        .status-badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .status-running { background: #28a745; color: white; }
        .status-stopped { background: #ffc107; color: black; }
        .status-missing { background: #dc3545; color: white; }
        .status-offline { background: #6c757d; color: white; }
        .timestamp { text-align: right; color: #666; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Reporte de Auditoría CrowdStrike Falcon Sensor</h1>

        <div class="summary">
            <div class="stat-box installed">
                <div class="stat-label">Instalados</div>
                <div class="stat-number">$installed</div>
                <div>$installedPercent%</div>
            </div>
            <div class="stat-box missing">
                <div class="stat-label">No Instalados</div>
                <div class="stat-number">$notInstalled</div>
            </div>
            <div class="stat-box offline">
                <div class="stat-label">Offline</div>
                <div class="stat-number">$offline</div>
            </div>
            <div class="stat-box total">
                <div class="stat-label">Total Equipos</div>
                <div class="stat-number">$total</div>
            </div>
        </div>

        <h2>Detalle de Equipos</h2>
        <table>
            <thead>
                <tr>
                    <th>Equipo</th>
                    <th>Estado</th>
                    <th>Servicio</th>
                    <th>Inicio Automático</th>
                    <th>Versión</th>
                    <th>Tiempo Respuesta (ms)</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($item in $Results | Sort-Object Status, Computer) {
        $badgeClass = switch -Wildcard ($item.Status) {
            "*Running*" { "status-running" }
            "*Not Running*" { "status-stopped" }
            "Not Installed" { "status-missing" }
            "Offline" { "status-offline" }
            default { "status-offline" }
        }

        $version = if ($item.Version) { $item.Version } else { "-" }
        $serviceStatus = if ($item.ServiceStatus) { $item.ServiceStatus } else { "-" }
        $startType = if ($item.ServiceStartType) { $item.ServiceStartType } else { "-" }
        $responseTime = if ($item.ResponseTime) { [math]::Round($item.ResponseTime, 0) } else { "-" }

        $html += @"
                <tr>
                    <td>$($item.Computer)</td>
                    <td><span class="status-badge $badgeClass">$($item.Status)</span></td>
                    <td>$serviceStatus</td>
                    <td>$startType</td>
                    <td>$version</td>
                    <td>$responseTime</td>
                </tr>
"@
    }

    $html += @"
            </tbody>
        </table>

        <div class="timestamp">
            Generado: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        </div>
    </div>
</body>
</html>
"@

    return $html
}

#endregion

#region Script Principal

# Inicializar variables
$script:OutputPath = $OutputPath
$script:MaxThreads = $MaxThreads
$script:RetryAttempts = $RetryAttempts
$script:Timeout = $Timeout
$script:LogFile = Join-Path $OutputPath "CrowdStrike_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Crear directorio de salida si no existe
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Log "=== Iniciando Auditoría de CrowdStrike Falcon Sensor ===" "INFO"
Write-Log "Parámetros: MaxThreads=$MaxThreads, RetryAttempts=$RetryAttempts, Timeout=$Timeout" "INFO"

# Verificar módulo de Active Directory
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "El módulo ActiveDirectory no está disponible. Instálelo con: Install-WindowsFeature RSAT-AD-PowerShell" "ERROR"
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop
Write-Log "Módulo ActiveDirectory cargado correctamente" "SUCCESS"

# Obtener equipos del dominio
Write-Log "Obteniendo lista de equipos del dominio..." "INFO"
try {
    $computers = Get-ADComputer -Filter { Enabled -eq $true } -Property Name, OperatingSystem, LastLogonDate |
                 Select-Object Name, OperatingSystem, LastLogonDate
    Write-Log "Se encontraron $($computers.Count) equipos habilitados en el dominio" "SUCCESS"
} catch {
    Write-Log "Error al obtener equipos del dominio: $($_.Exception.Message)" "ERROR"
    exit 1
}

if ($computers.Count -eq 0) {
    Write-Log "No se encontraron equipos en el dominio" "WARNING"
    exit 0
}

# Procesar equipos en paralelo
Write-Log "Iniciando escaneo de $($computers.Count) equipos..." "INFO"

$results = @()
$completed = 0
$totalComputers = $computers.Count

# Usar RunspacePool para procesamiento paralelo
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$runspacePool.Open()

$jobs = @()

foreach ($computer in $computers) {
    $powerShell = [powershell]::Create()
    $powerShell.RunspacePool = $runspacePool

    [void]$powerShell.AddScript({
        param($ComputerName, $RetryAttempts, $Timeout)

        $result = [PSCustomObject]@{
            Computer = $ComputerName
            Status = "Unknown"
            ServiceStatus = $null
            ServiceStartType = $null
            Version = $null
            InstallPath = $null
            LastChecked = Get-Date
            ResponseTime = $null
        }

        $pingStart = Get-Date

        $isOnline = $false
        for ($i = 1; $i -le $RetryAttempts; $i++) {
            if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -TimeoutSeconds $Timeout) {
                $isOnline = $true
                break
            }
            if ($i -lt $RetryAttempts) {
                Start-Sleep -Milliseconds 500
            }
        }

        $result.ResponseTime = ((Get-Date) - $pingStart).TotalMilliseconds

        if (-not $isOnline) {
            $result.Status = "Offline"
            return $result
        }

        try {
            $service = Get-Service -ComputerName $ComputerName -Name "CSFalconService" -ErrorAction Stop

            $result.ServiceStatus = $service.Status.ToString()
            $result.ServiceStartType = $service.StartType.ToString()

            try {
                $regPath = "SOFTWARE\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default"
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $key = $reg.OpenSubKey($regPath)

                if ($key) {
                    $result.Version = $key.GetValue("Version")
                    $result.InstallPath = $key.GetValue("InstallPath")
                    $key.Close()
                }
                $reg.Close()
            } catch { }

            if ($service.Status -eq "Running") {
                $result.Status = "Installed and Running"
            } else {
                $result.Status = "Installed but Not Running"
            }

        } catch {
            $result.Status = "Not Installed"
        }

        return $result
    })

    [void]$powerShell.AddArgument($computer.Name)
    [void]$powerShell.AddArgument($RetryAttempts)
    [void]$powerShell.AddArgument($Timeout)

    $jobs += [PSCustomObject]@{
        PowerShell = $powerShell
        Handle = $powerShell.BeginInvoke()
    }
}

# Recopilar resultados
Write-Host ""
while ($jobs.Handle.IsCompleted -contains $false) {
    $completedNow = ($jobs.Handle.IsCompleted | Where-Object { $_ -eq $true }).Count
    if ($completedNow -ne $completed) {
        $completed = $completedNow
        $percent = [math]::Round(($completed / $totalComputers) * 100, 1)
        Write-Progress -Activity "Escaneando equipos" -Status "$completed de $totalComputers equipos procesados ($percent%)" -PercentComplete $percent
    }
    Start-Sleep -Milliseconds 200
}

Write-Progress -Activity "Escaneando equipos" -Completed

foreach ($job in $jobs) {
    $result = $job.PowerShell.EndInvoke($job.Handle)
    $results += $result
    $job.PowerShell.Dispose()
}

$runspacePool.Close()
$runspacePool.Dispose()

Write-Log "Escaneo completado" "SUCCESS"

# Mostrar resumen en consola
Write-Host ""
Write-Log "=== RESUMEN ===" "INFO"
$installed = ($results | Where-Object { $_.Status -like "*Installed*" }).Count
$notInstalled = ($results | Where-Object { $_.Status -eq "Not Installed" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$installedRunning = ($results | Where-Object { $_.Status -eq "Installed and Running" }).Count
$installedNotRunning = ($results | Where-Object { $_.Status -eq "Installed but Not Running" }).Count

Write-Log "Total de equipos: $totalComputers" "INFO"
Write-Log "CrowdStrike instalado y corriendo: $installedRunning" "SUCCESS"
Write-Log "CrowdStrike instalado pero detenido: $installedNotRunning" "WARNING"
Write-Log "CrowdStrike NO instalado: $notInstalled" "ERROR"
Write-Log "Equipos offline: $offline" "WARNING"

# Generar reportes
Write-Host ""
Write-Log "Generando reportes..." "INFO"
Export-Reports -Results $results

Write-Host ""
Write-Log "=== Auditoría completada ===" "SUCCESS"
Write-Log "Revise los archivos generados en: $OutputPath" "INFO"

#endregion
