[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [String]$keyVaultName,

  [Parameter(Mandatory=$true)]
  [String]$principalName,

  [Parameter()]
  [int]$validityInMonths = 12
)

function New-SelfSignedCert {
  param($keyVault, $certificateName, $subjectName, $validityInMonths, $renewDaysBefore)

  $kvPolicy = New-AzKeyVaultCertificatePolicy `
              -SubjectName $subjectName `
              -ReuseKeyOnRenewal `
              -IssuerName 'Self' `
              -ValidityInMonths $validityInMonths `
              -RenewAtNumberOfDaysBeforeExpiry $renewDaysBefore

  $operation = Add-AzKeyVaultCertificate `
              -VaultName $keyVault `
              -CertificatePolicy $kvPolicy `
              -Name $certificateName

  while ( $operation.Status -ne 'completed' ) {
    Start-Sleep -Seconds 1
    $operation = Get-AzKeyVaultCertificateOperation -VaultName $keyVault -Name $certificateName
  }
  (Get-AzKeyVaultCertificate -VaultName $keyVault -Name $certificateName).Certificate
}

$certName = "SPCert-$principalName"
$cert = New-SelfSignedCert -keyVault $keyVaultName `
                                   -certificateName $certName `
                                   -subjectName "CN=$principalName" `
                                   -validityInMonths $validityInMonths `
                                   -renewDaysBefore 1

Write-Verbose "Created certificate - Thumbprint:$($cert.Thumbprint)"

$certString = [Convert]::ToBase64String($cert.GetRawCertData())

New-AzADServicePrincipal -DisplayName $principalName `
                              -CertValue $certString `
                              -EndDate $cert.NotAfter.AddDays(-1)