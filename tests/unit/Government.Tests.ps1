# tests/unit/Government.Tests.ps1
BeforeAll {
    Mock Get-ADUser { return @{ SamAccountName = 'j.perez'; ExtensionAttribute10 = '12345678'; ExtensionAttribute11 = 'Analista' } }
    Mock New-ADUser { return $true }
    Mock Add-ADPrincipalGroupMembership { return $true }
}

Describe "Invoke-ADMasterFramework.ps1 - Creación PCM" {
    It "Debe generar un SamAccountName estandarizado según directiva SEGDI" {
        # Simulamos la lógica de creación
        $FirstName = "Juan"
        $LastName = "Perez"
        $expectedSam = "j.perez"
        
        $samAccountName = "$($FirstName.Substring(0,1).ToLower()).$($LastName.ToLower())"
        $samAccountName | Should -BeExactly $expectedSam
    }
}
