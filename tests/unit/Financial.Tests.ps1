# tests/unit/Financial.Tests.ps1
BeforeAll {
    # Mock de funciones de AD para evitar ejecutar contra un dominio real durante pruebas
    Mock Get-ADUser { return @{ SamAccountName = 'testuser'; DistinguishedName = 'CN=testuser,OU=Test,DC=banco,DC=com,DC=pe' } }
    Mock Disable-ADAccount { return $true }
    Mock Move-ADObject { return $true }
    Mock Set-ADAccountPassword { return $true }
    Mock Write-EventLog { return $true }
}

Describe "Invoke-NAIF_AD_Automation.ps1 - Offboarding" {
    It "Debe fallar si el archivo CSV no existe" {
        { . ./src/powershell/financial/Invoke-NAIF_AD_Automation.ps1 -Action 'Offboard' -InputFilePath 'C:\inexistente.csv' } | Should -Throw "Archivo de entrada no encontrado"
    }
    
    It "Debe ejecutar el flujo de offboarding sin errores cuando el archivo es válido" {
        # Crear CSV temporal
        $tempCsv = New-TemporaryFile
        "ID_Empleado`n12345" | Out-File $tempCsv -Encoding UTF8
        
        $result = . ./src/powershell/financial/Invoke-NAIF_AD_Automation.ps1 -Action 'Offboard' -InputFilePath $tempCsv.FullName
        
        $result.Status | Should -Be "Success"
        Remove-Item $tempCsv
    }
}
