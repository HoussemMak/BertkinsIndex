using module "..\ORCA.psm1"

class ORCA235 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA235()
    {
        $this.Control="235"
        $this.Area=Get-LocalizedString -Key "ORCA235_Area"
        $this.Name=Get-LocalizedString -Key "ORCA235_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA235_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA235_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA235_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA235_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA235_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA235_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA235_Link_UseSPF")="https://aka.ms/orca-spf-docs-1"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # Check pre-requisites for DNS resolution
        If(!(Get-Command "Resolve-DnsName" -ErrorAction:SilentlyContinue))
        {
            # No Resolve-DnsName command
            ForEach($AcceptedDomain in $Config["AcceptedDomains"])
            {
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object = $($AcceptedDomain.Name)
                $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
                $ConfigObject.ConfigItem = "Pre-requisites not installed"
                $ConfigObject.ConfigData = "Resolve-DnsName is not found on ORCA computer. Required for DNS checks."
                $this.AddConfig($ConfigObject)
            }

            $this.CheckFailed = $true
            $this.CheckFailureReason = "Resolve-DnsName is not found on ORCA computer and is required for DNS checks."
            
        }
        else 
        {
            # Check SPF
            ForEach($AcceptedDomain in $Config["AcceptedDomains"]) 
            {  
                $SplatParameters = @{
                    'ErrorAction' = 'SilentlyContinue'
                }

                # If alternate DNS specified, add Server param
                if($null -ne $this.ORCAParams.AlternateDNS)
                {
                    $SplatParameters["Server"] = $this.ORCAParams.AlternateDNS
                }

                $HasMailbox = $false

                try
                {
                    $mailbox = Resolve-DnsName -Name $($AcceptedDomain.Name) -Type MX -ErrorAction:Stop @SplatParameters

                    if($null -ne $mailbox -and $mailbox.Count -gt 0)
                    {
                        $HasMailbox = $true
                    }
                }
                Catch{}
                
                If($HasMailbox) 
                {   
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.Object = $($AcceptedDomain.Name)

                    $SPF = Resolve-DnsName -Name $($AcceptedDomain.Name) -Type TXT @SplatParameters | where-object { $_.strings -match "v=spf1" } | Select-Object -ExpandProperty strings -ErrorAction SilentlyContinue
                    if ($SPF -match "redirect") {
                        $redirect = $SPF.Split(" ")
                        $RedirectName = $redirect -match "redirect" -replace "redirect="
                        $SPF = Resolve-DnsName -Name "$RedirectName" -Type TXT @SplatParameters | where-object { $_.strings -match "v=spf1" } | Select-Object -ExpandProperty strings -ErrorAction SilentlyContinue
                    }

                    $SpfAdvisory = Get-LocalizedString -Key "ORCA235_SpfAdvisory_NoSPFRecord"
                    if ( $null -eq $SPF) {
                        $SpfAdvisory = Get-LocalizedString -Key "ORCA235_SpfAdvisory_NoSPFRecord"
                    }
                    if ($SPF -is [array]) {
                        $SpfAdvisory = Get-LocalizedString -Key "ORCA235_SpfAdvisory_MultipleSPFRecords"
                    }
                    Else {
                        switch -Regex ($SPF) {
                        '~all' {
                            $SpfAdvisory = Get-LocalizedString -Key "ORCA235_SpfAdvisory_SoftFail"
                        }
                        '-all' {
                            $SpfAdvisory = Get-LocalizedString -Key "ORCA235_SpfAdvisory_HardFail"
                        }
                        Default {
                            $SpfAdvisory = Get-LocalizedString -Key "ORCA235_SpfAdvisory_NoQualifier"
                        }
                    }
                    }

                    # Get matching DKIM signing configuration          
        
                    If($true)
                    {
                        $ConfigObject.ConfigItem="$($SPF)"

                        if($SpfAdvisory -eq "Hard Fail")
                        {
                            $ConfigObject.ConfigData = "Yes"
                        }
                        Elseif( ($SpfAdvisory -eq "Soft Fail") -or ($SpfAdvisory -eq "No qualifier found"))
                        {
                            $ConfigObject.ConfigData = "No"
                        }
                        Else
                        {
                            $ConfigObject.ConfigData = "Not Detected"
                        }

                        if($SpfAdvisory -eq "Hard Fail")
                        {
                            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                        }
                        Else 
                        {
                            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                        }
                    }
                    Else
                    {
                        $ConfigObject.ConfigItem = "Not Detected"
                        $ConfigObject.ConfigData = "Not Detected"
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    }

                    # Add config to check
                    $this.AddConfig($ConfigObject)
                }   
            }    
        }
       
    }
}
