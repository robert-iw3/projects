function Get-DbsBrowser {
    <#
    .SYNOPSIS
        Gets non-compliant SQL Browser service states (Running)

    .DESCRIPTION
        Gets non-compliant SQL Browser service states (Running)

    .PARAMETER ComputerName
        The target server or instance

    .PARAMETER Credential
        Login to the target computer using alternative credentials

    .PARAMETER EnableException
        By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
        This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
        Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

    .NOTES
        Tags: V-79353, V-79349, NonCompliantResults


    .EXAMPLE
        PS C:\> Get-DbsBrowser -ComputerName Sql2016

       Gets non-compliant SQL Browser services
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory, ValueFromPipeline)]
        [DbaInstanceParameter[]]$ComputerName,
        [PSCredential]$Credential,
        [switch]$EnableException
    )
    process {
        Get-DbaService @PSBoundParameters -Type Browser | Where-Object State -eq Running
    }
}