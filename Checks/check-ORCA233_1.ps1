using module "..\ORCA.psm1"

class ORCA233_1 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA233_1()
    {
        $this.Control="233_1"
        $this.Area=Get-LocalizedString -Key "ORCA233_1_Area"
        $this.Name=Get-LocalizedString -Key "ORCA233_1_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA233_1_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA233_1_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA233_1_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA233_1_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA233_1_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA233_1_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA233_1_Link_EnhancedFiltering")="https://aka.ms/orca-connectors-action-skiplisting"
            (Get-LocalizedString -Key "ORCA233_1_Link_ConnectorsDocs")="https://aka.ms/orca-connectors-docs-1"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $Connectors = @()

        # Analyze connectors
        ForEach($Connector in $($Config["InboundConnector"] | Where-Object {$_.Enabled}))
        {
            # Set regex options for later match
            $options = [Text.RegularExpressions.RegexOptions]::IgnoreCase

            ForEach($senderdomain in $Connector.SenderDomains)
            {
                # Perform match on sender domain
                $match = [regex]::Match($senderdomain,"^smtp:\*;(\d*)$",$options)

                if($match.success)
                {
                    # Positive match
                    $Connectors += New-Object -TypeName PSObject -Property @{
                        Identity=$Connector.Identity
                        Priority=$($match.Groups[1].Value)
                        TlsSenderCertificateName=$Connector.TlsSenderCertificateName
                        EFTestMode=$Connector.EFTestMode
                        EFSkipLastIP=$Connector.EFSkipLastIP
                        EFSkipIPs=$Connector.EFSkipIPs
                        EFSkipMailGateway=$Connector.EFSkipMailGateway
                        EFUsers=$Connector.EFUsers
                    }
                }
            }

        }

        # Determine if skip listing is required
        $SkipListRequired = $False
        $NonEOPRecords = @($Config["MXReports"] | Where-Object {$_.PointsToService -eq $False})

        If($NonEOPRecords.Count -gt 0)
        {
            $SkipListRequired = $True
        }

        If($Connector.Count -eq 0 -and $SkipListRequired)
        {
            # No connectors so we should fail
            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=Get-LocalizedString -Key "ORCA233_1_NoConnectors"
            $ConfigObject.ConfigItem = "-"
            $ConfigObject.ConfigData = "None"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }

        # Add config data for each connector
        ForEach($Connector in $Connectors) 
        {

            # Construct config object

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($Connector.Identity)

            If($SkipListRequired)
            {
                If($Connector.EFSkipLastIP)
                {
                    $ConfigObject.ConfigItem = Get-LocalizedString -Key "ORCA233_1_LastIP"
                    $ConfigObject.ConfigData = "Last IP"
                } ElseIf($Connector.EFSkipIPs.Count -gt 0)
                {
                    $ConfigObject.ConfigItem = Get-LocalizedString -Key "ORCA233_1_SkipIPs"
                    $ConfigObject.ConfigData = $Connector.EFSkipIPs
                } Else
                {
                    $ConfigObject.ConfigItem = Get-LocalizedString -Key "ORCA233_1_NotConfigured"
                    $ConfigObject.ConfigData = "None"
                }
    
                # Determine that EF is set to a mode, no test mode, and no select users
                If(($Connector.EFSkipLastIp -eq $True -or $Connector.EFSkipIPs.Count -gt 0) -and $Connector.EFTestMode -eq $False -and $Connector.EFUsers.Count -eq 0)
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                }
                else
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }
    
                If($Connector.EFTestMode)
                {
                    $ConfigObject.ConfigItem += Get-LocalizedString -Key "ORCA233_1_TestMode"
                }
    
                If($Connector.EFUsers.Count -gt 0)
                {
                    $ConfigObject.ConfigItem += Get-LocalizedString -Key "ORCA233_1_SelectUsers"
                }
            }
            else 
            {
                # Not required
                $ConfigObject.ConfigItem = Get-LocalizedString -Key "ORCA233_1_NotRequired"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }

            $this.AddConfig($ConfigObject)

        }

    }

}
