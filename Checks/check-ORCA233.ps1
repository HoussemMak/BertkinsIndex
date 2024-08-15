using module "..\ORCA.psm1"

class ORCA233 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA233()
    {
        $this.Control=233
        $this.Area=Get-LocalizedString -Key "ORCA233_Area"
        $this.Name=Get-LocalizedString -Key "ORCA233_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA233_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA233_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA233_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA233_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA233_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA233_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA233_Link_EnhancedFiltering")="https://aka.ms/orca-connectors-action-skiplisting"
            (Get-LocalizedString -Key "ORCA233_Link_ConnectorsDocs")="https://aka.ms/orca-connectors-docs-1"
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

        $EFDisabledConnectors = @($Connectors | Where-Object {($_.EFSkipIPs.Count -eq 0 -and $_.EFSkipLastIP -eq $False) -or $_.EFTestMode -eq $True -or $_.EFUsers.Count -gt 0})

        If($EFDisabledConnectors.Count -gt 0 -or $Connectors.Count -eq 0)
        {
            $EnhancedFiltering = $False
        }
        else
        {
            $EnhancedFiltering = $True
        }

        ForEach($Domain in $Config["AcceptedDomains"]) 
        {

            # Get the MX record report for this domain

            $MXRecords = @($Config["MXReports"] | Where-Object {$_.Domain -eq $($Domain.DomainName)})

            # Construct config object

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$($Domain.Name)

            If($MXRecords.PointsToService -Contains $False)
            {
                $PointsToService = $False
            }
            else
            {
                $PointsToService = $True
            }

            If($PointsToService)
            {

                $ConfigObject.ConfigItem="Yes"
                $ConfigObject.ConfigData="Not Required"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

            }
            else
            {
                $ConfigObject.ConfigItem="No"

                If($EnhancedFiltering)
                {
                    $ConfigObject.ConfigData="Configured"
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                }
                else
                {
                    $ConfigObject.ConfigData="Not Configured"
                    $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
                    $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA233_InfoText"
                }
            }

            $this.AddConfig($ConfigObject)

        }

    }

}
