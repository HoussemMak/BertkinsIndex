using module "..\ORCA.psm1"

class ORCA108 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA108()
    {
        $this.Control="108"
        $this.Area=Get-LocalizedString -Key "ORCA108_Area"
        $this.Name=Get-LocalizedString -Key "ORCA108_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA108_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA108_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA108_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA108_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA108_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA108_Link_DefenderPortal")="https://security.microsoft.com/authentication?viewid=DKIM"
            (Get-LocalizedString -Key "ORCA108_Link_UseDKIM")="https://aka.ms/orca-dkim-docs-1"
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
            # Check DKIM is enabled
        
            ForEach($AcceptedDomain in $Config["AcceptedDomains"]) 
            {
                $HasMailbox = $false
                
                try
                {
                    
                    If($AcceptedDomain.Name -notlike "*.onmicrosoft.com") 
                    { 
                        $mailbox = Resolve-DnsName -Name $($AcceptedDomain.Name) -Type MX -ErrorAction:Stop
                        if($null -ne $mailbox -and $mailbox.Count -gt 0)
                        {
                            $HasMailbox = $true
                        }
                    }
                }
                Catch{}
                If($HasMailbox) 
                {
        
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.ConfigItem=$($AcceptedDomain.Name)

                    # Get matching DKIM signing configuration
                    $DkimSigningConfig = $Config["DkimSigningConfig"] | Where-Object {$_.Name -eq $AcceptedDomain.Name}
        
                    If($DkimSigningConfig)
                    {
                        $ConfigObject.ConfigData=$($DkimSigningConfig.Enabled)

                        if($DkimSigningConfig.Enabled -eq $true)
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
                        $ConfigObject.ConfigData="No Configuration"
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    }

                    # Add config to check
                    $this.AddConfig($ConfigObject)
        
                }
        
            }         
        }

    }

}
