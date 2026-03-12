# Importar módulo de Active Directory
Import-Module ActiveDirectory

# Obtener todas las computadoras habilitadas del dominio
$computers = Get-ADComputer -Filter * -Property Name | Select-Object -ExpandProperty Name

# Crear arrays para resultados
$CrowdStrikeInstalled = @()
$CrowdStrikeMissing = @()
$OfflineComputers = @()

foreach ($computer in $computers) {

    Write-Host "Verificando $computer ..." -ForegroundColor Cyan

    # Verificar si el equipo responde
    if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {

        try {
            $service = Get-Service -ComputerName $computer -Name "CSFalconService" -ErrorAction Stop

            if ($service.Status) {
                $CrowdStrikeInstalled += $computer
            }

        } catch {
            $CrowdStrikeMissing += $computer
        }

    } else {
        $OfflineComputers += $computer
    }
}

# Mostrar resultados
Write-Host "=============================="
Write-Host "Equipos con CrowdStrike:" -ForegroundColor Green
$CrowdStrikeInstalled

Write-Host "=============================="
Write-Host "Equipos SIN CrowdStrike:" -ForegroundColor Red
$CrowdStrikeMissing

Write-Host "=============================="
Write-Host "Equipos OFFLINE:" -ForegroundColor Yellow
$OfflineComputers

# Exportar resultados a CSV
$report = @()

foreach ($pc in $CrowdStrikeInstalled) {
    $report += [PSCustomObject]@{
        Computer = $pc
        Status = "CrowdStrike Installed"
    }
}

foreach ($pc in $CrowdStrikeMissing) {
    $report += [PSCustomObject]@{
        Computer = $pc
        Status = "CrowdStrike Missing"
    }
}

foreach ($pc in $OfflineComputers) {
    $report += [PSCustomObject]@{
        Computer = $pc
        Status = "Offline"
    }
}

$report | Export-Csv "Crowdstrike_Audit.csv" -NoTypeInformation