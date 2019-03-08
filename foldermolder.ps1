<#
    .SYNOPSIS
        FolderMolder

    .DESCRIPTION
        Monitors folder permissions on mailbox.
        Permissions are based of whitelist in .json format.

    .NOTES
        Author: pwrstrm
        Date: 2019-02-01
        Version: 1.0.0

    .CHANGELOG
        2019-02-01: Developed script.
        
#>
cls

# Configuration
$mailboxAddress = "" # Mailbox to monitor
$sendTo = "" # Address to send to
$sendFrom = "" # Address to send from

# Path to log findings
$logPath = "D:\FolderMolder\logs\"
(Get-Date).ToString("yyyy-MM-dd HH:mm:ss") | Add-Content ($logPath + "runtime.txt")

# Clearing Error variable
$error.Clear()

# Sends E-Mail Message using Exchange Web Services (EWS)
Function Send-EWSMail
{
    Param
    (
        [Microsoft.Exchange.WebServices.Data.ExchangeService]$ews,
        
        # Sender & reciever
        [String]$from,
        [String]$to,

        # Subject
        [String]$subject = "Mailbox Folder Breach!",

        # Folder name
        [String]$folder,

        # Breach User
        [String]$user,
        
        # Permission User should have
        [String]$rightPerm,

        # Permission User have right now
        [String]$wrongPerm,

        # Path to folder in Mailbox
        [String]$folderPath,

        [String]$logPath
    )

    # Subject & Body
    $message = New-Object Microsoft.Exchange.WebServices.Data.EmailMessage -ArgumentList $ews  
    $message.Subject = $subject

    $report = [PSCustomObject]@{
        Folder = $folder
        "User/Group" = $user
        Default = $rightPerm
        Current = $wrongPerm
        Path = $folderPath
    }

    $htmlBody = New-Object System.Collections.ArrayList(,($report | ConvertTo-Html))
    $htmlBody.RemoveRange(0,5)
    $htmlBody.RemoveAt(($htmlBody.Count -1))

    $htmlBodyBegin = gc -Path "D:\FolderMolder\template_begin.html" -Encoding UTF8
    $htmlBodyMiddle = gc -Path "D:\FolderMolder\template.html" -Encoding UTF8
    $htmlBodyEnd = gc -Path "D:\FolderMolder\template_end.html" -Encoding UTF8

    $message.Body = New-Object Microsoft.Exchange.WebServices.Data.MessageBody
    $message.Body.BodyType = [Microsoft.Exchange.WebServices.Data.BodyType]::HTML
    $message.Body.Text = $htmlBodyBegin + $htmlBodyMiddle + $htmlBody + $htmlBodyEnd

    # Sender & Reciever
    $message.From = New-Object Microsoft.Exchange.WebServices.Data.EmailAddress($from)
    $message.Sender = New-Object Microsoft.Exchange.WebServices.Data.EmailAddress($from)
    $message.ToRecipients.Add("se.sd.service.tools@cgi.com") | Out-Null

    # Sending Message
    $message.Send()

    # Logging findings
    $report.Folder + ";" + $report."User/Group" + ";" + $report.Default + ";" + $report.Current + ";" + $report.Path + ";" | Add-Content ($logPath + "logfile.txt")

    Write-Host "Mail was sent.." -f cyan
}

# Shows permissions by locating folder by id
Function Get-EWSFolderPermisson
{
    Param
    (
        $Exchange,
        $folderId
    )

    $property = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)  
    $property.Add([Microsoft.Exchange.WebServices.Data.FolderSchema]::Permissions)
    $folderPermission = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Exchange,$folderId,$property)
    
    Return $folderPermission
}

# Configuration & .dll file
$json = ((Get-Content "D:\FolderMolder\whitelist.json").Replace("\","\\")) -join "`n" | ConvertFrom-Json
$mailboxName = $mailboxAddress
Add-Type -Path $PSScriptRoot\Microsoft.Exchange.WebServices.dll

# Exchange Versions to choose from
$Exchange2007SP1 = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2007_SP1
$Exchange2010    = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010
$Exchange2010SP1 = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP1
$Exchange2010SP2 = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2
$Exchange2013    = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013
$Exchange2013SP1 = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1

# Configuration for 'Exchange Web Server'
$ExchangeVersion = $Exchange2010SP2
$ews = New-Object -TypeName Microsoft.Exchange.WebServices.Data.ExchangeService -ArgumentList $ExchangeVersion

$windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sidbind = "LDAP://<SID=" + $windowsIdentity.user.Value.ToString() + ">"
$aceuser = [ADSI]$sidbind
$ews.AutodiscoverUrl($aceuser.mail.ToString(), {$true})

$rootFoldername = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox
$rootId = New-Object Microsoft.Exchange.WebServices.Data.FolderId($rootFolderName, $mailboxName)
$rootFolder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($ews, $rootId)

# Locating Inbox Folder
$FolderView = New-Object Microsoft.Exchange.WebServices.Data.FolderView(1000)
$FolderView.Traversal = [Microsoft.Exchange.WebServices.Data.FolderTraversal]::Shallow

Function Get-Folder
{
    Param
    (
        # Data Folder
        $folder,

        # Folder path string
        [String]$folderPath,
        
        # Recursive permission
        $Permission,

        [String]$logPath
    )

    # Iterating folders
    Foreach($child in $folder.FindFolders($FolderView).Folders)
    {
        # Generating Folder Path
        $folderString = $folderPath + "\" + $child.DisplayName
        Write-Host $folderString -f Yellow

        # Folder name found
        if($json.($child.DisplayName))
        {
            # All permissions on folder
            Foreach($perm in (Get-EWSFolderPermisson $ews $child.Id).Permissions)
            {
                if($perm.UserId.DisplayName)
                {
                    # Locating permission from .json file
                    $userPermission = $null
                    $userPermission = $json.($child.DisplayName).Permissions.($perm.UserId.DisplayName)
                    
                    # Permission not empty
                    if($userPermission)
                    {
                        if($perm.PermissionLevel -ne $userPermission)
                        {
                            Write-Host $folderString -f Red

                            Send-EWSMail -ews $ews `
                            -to $sendTo `
                            -from $sendFrom `
                            -folder $child.DisplayName `
                            -user ($perm.UserId.DisplayName).ToString() `
                            -rightPerm $userPermission `
                            -wrongPerm ($perm.PermissionLevel) `
                            -folderPath $folderString -logPath $logPath
                        }
                    }
                    # Permission User not found in .json white list
                    else
                    {
                        if($perm.PermissionLevel -ne "None")
                        {
                            Write-Host $folderString -f Red
                            
                            if($perm.UserId.DisplayName)
                            {
                                Send-EWSMail -ews $ews `
                                -to $sendTo `
                                -from $sendFrom `
                                -folder $child.DisplayName `
                                -user ($perm.UserId.DisplayName).ToString() `
                                -rightPerm "n/a" `
                                -wrongPerm ($perm.PermissionLevel) `
                                -folderPath $folderString -logPath $logPath
                            }
                        }
                    }
                }
            }

            # Recursive check
            if($json.($child.DisplayName).Recursive -eq $true)
            {
                Get-Folder $child -folderPath $folderString -Permission $json.($child.DisplayName).Permissions
            }
            # Non recursive check
            else
            {
                Get-Folder $child -folderPath $folderString
            }
        }
        # Folder name not found
        else
        {
            # Recursive permissions found
            if($Permission)
            {
                # Iterates current permissions on folder
                Foreach($perm in (Get-EWSFolderPermisson $ews $child.Id).Permissions)
                {
                    # Recursive permission from last folder
                    $userPermission = $null
                    $userPermission = $Permission.($perm.UserId.DisplayName)

                    # 
                    if($userPermission)
                    {
                        if($perm.PermissionLevel -ne $userPermission)
                        {
                            Write-Host $folderString -f Red

                            Send-EWSMail -ews $ews `
                            -to $sendTo `
                            -from $sendFrom `
                            -folder $child.DisplayName `
                            -user ($perm.UserId.DisplayName).ToString() `
                            -rightPerm $userPermission `
                            -wrongPerm ($perm.PermissionLevel) `
                            -folderPath $folderString
                        }
                    }
                }
            }
            else
            {
                # Do nothing
            }

            Get-Folder $child -folderPath $folderString -logPath $logPath
        }
    }
}

Get-Folder $rootFolder -folderPath "Inbox" -logPath $logPath

# Logging Errors
if($error)
{
    $error.Exception.Message | Add-Content ($logPath + "errors.txt")
}
