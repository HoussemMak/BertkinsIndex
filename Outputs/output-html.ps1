using module "..\ORCA.psm1"

class html : ORCAOutput
{

    $OutputDirectory=$null
    $DisplayReport=$True
    $EmbedConfiguration=$false

    html()
    {
        $this.Name="HTML"
    }

    RunOutput($Checks,$Collection,[ORCAConfigLevel]$AssessmentLevel)
    {
    <#

        OUTPUT GENERATION / Header

    #>

    # Obtain the tenant domain and date for the report
    $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName
    $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
    $ReportDate = $(Get-Date -format 'dd-MMM-yyyy HH:mm')

    # Summary Where-Object {$_.Completed -eq $true}
    $RecommendationCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Fail -and $_.Completed -eq $true}).Count
    $OKCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Pass -and $_.Completed -eq $true}).Count
    $InfoCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Informational -and $_.Completed -eq $true}).Count

    # Misc
    $ReportTitle = $(Get-LocalizedString -Key 'ReportTitle')
    $ReportSub1 = $(Get-LocalizedString -Key 'ReportSub1')
    $ReportSub2 = $(Get-LocalizedString -Key 'ReportSub2')
    $EmbeddedConfiguration = $(Get-LocalizedString -Key 'EmbeddedConfiguration')
    $EmbeddedConfigurationMessage = $(Get-LocalizedString -Key 'EmbeddedConfigurationMessage')
    $ORCAOutOfDate = $(Get-LocalizedString -Key 'ORCAOutOfDate')
    $VersionChecksDisabled = $(Get-LocalizedString -Key 'VersionChecksDisabled')
    $PreviewVersion = $(Get-LocalizedString -Key 'PreviewVersion')
    $MDOServiceNotDetected = $(Get-LocalizedString -Key 'MDOServiceNotDetected')
    $CheckFailed = $(Get-LocalizedString -Key 'CheckFailed')
    $Informational = $(Get-LocalizedString -Key 'Informational')
    $Recommendation = $(Get-LocalizedString -Key 'Recommendation')
    $OK = $(Get-LocalizedString -Key 'OK')
    $SecurityScoreText = $(Get-LocalizedString -Key 'SecurityScoreText')
    $ConfigHealthIndex = $(Get-LocalizedString -Key 'ConfigHealthIndex')
    $Summary = $(Get-LocalizedString -Key 'Summary')
    $Legend = $(Get-LocalizedString -Key 'Legend')

    # Area icons
    $AreaIcon = @{}
    $AreaIcon["Default"] = "fas fa-user-cog"
    $AreaIcon["Connectors"] = "fas fa-plug"
    $AreaIcon["Anti-Spam Policies"] = "fas fa-trash"
    $AreaIcon["Malware Filter Policy"] = "fas fa-biohazard"
    $AreaIcon["Zero Hour Autopurge"] = "fas fa-trash"
    $AreaIcon["DKIM"] = "fas fa-file-signature"
    $AreaIcon["Transport Rules"] = "fas fa-list"
    $AreaIcon["Transport Rules"] = "fas fa-list"
	
	
	# Mapping des valeurs localisées vers les noms d'area en anglais ou clés communes
	$AreaMap = @{
    "Connecteurs" = "Connectors"
    "Connectors" = "Connectors"
    "Politiques Anti-Spam" = "Anti-Spam Policies"
    "Anti-Spam Policies" = "Anti-Spam Policies"
    "Politique de Filtrage de Malware" = "Malware Filter Policy"
    "Malware Filter Policy" = "Malware Filter Policy"
    "Purge automatique de la dernière heure" = "Zero Hour Autopurge"
    "Zero Hour Autopurge" = "Zero Hour Autopurge"
    "DKIM" = "DKIM"
    "Règles de transport" = "Transport Rules"
    "Transport Rules" = "Transport Rules"
    # Ajoute les autres mappings ici...
}


    # Embed checks as JSON in to HTML file at beginning for charting/historic purposes
    $MetaObject = New-Object -TypeName PSObject -Property @{
        Tenant=$Tenant
        TenantDomain=$TenantDomain
        ReportDate=$ReportDate
        Version=$($this.VersionCheck.Version.ToString())
        Config=$null
        EmbeddedConfiguration=$this.EmbedConfiguration
        Summary=New-Object -TypeName PSObject -Property @{
            Recommendation=$RecommendationCount
            OK=$OKCount
            InfoCount=$InfoCount
        }
        Checks=$Checks
    }

    if($this.EmbedConfiguration -eq $true)
    {
        # Write in to temp file to use clixml
        $TempFileXML = New-TemporaryFile

        # Create the temp path for zip
        $ZipTempLoc = New-TemporaryFile
        $ZipPath = $($ZipTempLoc.ToString()) + ".zip"

        # Export collection to XML file
        $Collection | Export-Clixml -Path $TempFileXML

        # Compress the XML to ZIP
        Compress-Archive -Path $TempFileXML -DestinationPath $ZipPath

        # Store in meta object, on Core use AsByteStream, on other use -Encoding byte
        if($global:PSVersionTable.PSEdition -eq "Core")
        {
            $MetaObject.Config = [convert]::ToBase64String((Get-Content -path $ZipPath -AsByteStream))
        }
        else 
        {
            $MetaObject.Config = [convert]::ToBase64String((Get-Content -path $ZipPath -Encoding byte))
        }
        
        $MetaObject.EmbeddedConfiguration = $true

        # Clean-up paths
        Remove-Item -Path $TempFileXML
        Remove-Item -Path $ZipTempLoc
        Remove-Item -Path $ZipPath
    }

    $EncodedText = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($MetaObject | ConvertTo-Json -Depth 100)))
    $output = "<!-- checkjson`n"
    $output += $($EncodedText)
    $output += "`nendcheckjson -->"

    # Get historic report info
    $HistoricData = $this.GetHistoricData($MetaObject,$Tenant)

    # Output start
    $output += "<!doctype html>
    <html lang='en'>
    <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <script src='https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.7/dist/umd/popper.min.js' integrity='sha384-zYPOMqeu1DAVkHiLqWBUTcbYfZ8osu1Nd6Z89ify25QV9guujx43ITvfi12/QExE' crossorigin='anonymous'></script>

        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css' rel='stylesheet' integrity='sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ' crossorigin='anonymous'>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js' integrity='sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe' crossorigin='anonymous'></script>

        <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
        
        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/css/all.min.css' crossorigin='anonymous'>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/js/all.js'></script>

        <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
        <script src='https://cdn.jsdelivr.net/npm/moment@2.27.0'></script>
        <script src='https://cdn.jsdelivr.net/npm/chartjs-adapter-moment@0.1.1'></script>
        
        <style>
        .table-borderless td,
        .table-borderless th {
            border: 0;
        }
        .bd-callout {
            padding: 1rem;
            margin-top: 1rem;
            margin-bottom: 1rem;
            border: 1px solid #eee;
            border-left-width: .25rem;
            border-radius: .25rem
        }
        
        .bd-callout h4 {
            margin-top: 0;
            margin-bottom: .25rem
        }
        
        .bd-callout p:last-child {
            margin-bottom: 0
        }
        
        .bd-callout code {
            border-radius: .25rem
        }
        
        .bd-callout+.bd-callout {
            margin-top: -.25rem
        }
        
        .bd-callout-info {
            border-left-color: #5bc0de
        }
        
        .bd-callout-info h4 {
            color: #5bc0de
        }
        
        .bd-callout-warning {
            border-left-color: #f0ad4e
        }
        
        .bd-callout-warning h4 {
            color: #f0ad4e
        }
        
        .bd-callout-danger {
            border-left-color: #d9534f
        }
        
        .bd-callout-danger h4 {
            color: #d9534f
        }

        .bd-callout-success {
            border-left-color: #00bd19
        }

        .navbar-custom { 
            background-color: #005494;
            color: white; 
            padding-bottom: 10px;

            
        } 
        /* Modify brand and text color */ 
          
        .navbar-custom .navbar-brand, 
        .navbar-custom .navbar-text { 
            color: white; 
            padding-top: 70px;
            padding-bottom: 10px;

        } 
        .star-cb-group {
            /* remove inline-block whitespace */
            font-size: 0;
            /* flip the order so we can use the + and ~ combinators */
            unicode-bidi: bidi-override;
            direction: rtl;
            /* the hidden clearer */
          }
          .star-cb-group * {
            font-size: 1rem;
          }
          .star-cb-group > input {
            display: none;
          }
          .star-cb-group > input + label {
            /* only enough room for the star */
            display: inline-block;
            overflow: hidden;
            text-indent: 9999px;
            width: 1.7em;
            white-space: nowrap;
            cursor: pointer;
          }
          .star-cb-group > input + label:before {
            display: inline-block;
            text-indent: -9999px;
            content: ""\2606"";
            font-size: 30px;
            color: #005494;
          }
          .star-cb-group > input:checked ~ label:before, .star-cb-group > input + label:hover ~ label:before, .star-cb-group > input + label:hover:before {
            content:""\2605"";
            color: #e52;
          font-size: 30px;
            text-shadow: 0 0 1px #333;
          }
          .star-cb-group > .star-cb-clear + label {
            text-indent: -9999px;
            width: .5em;
            margin-left: -.5em;
          }
          .star-cb-group > .star-cb-clear + label:before {
            width: .5em;
          }
          .star-cb-group:hover > input + label:before {
            content: ""\2606"";
            color: #005494;
          font-size: 30px;
            text-shadow: none;
          }
          .star-cb-group:hover > input + label:hover ~ label:before, .star-cb-group:hover > input + label:hover:before {
            content: ""\2605"";
            color: #e52;
          font-size: 30px;
            text-shadow: 0 0 1px #333;
          }         
        </style>

        <title>$($ReportTitle)</title>

    </head>
    <body class='app header-fixed bg-light'>

        <nav class='navbar  fixed-top navbar-custom p-3 border-bottom d-print-block'>
            <div class='container-fluid'>
                <div class='col-sm' style='text-align:left'>
                    <div class='row'>
                        <div class='col col-md-auto'><i class='fas fa-binoculars'></i></div>
                        <div class='col'><strong>CM365</strong></div>
                    </div>
                </div>
                <div class='col-sm' style='text-align:center'>
                    <strong>Tenant : $($TenantDomain)</strong>
                </div>
                <div class='col-sm' style='text-align:right'>
                    $($ReportDate)
                </div>
            </div>
        </nav>  

            <div class='app-body p-3'>
            <main class='main'>
                <!-- Main content here -->
                <div class='container' style='padding-top:50px;'></div>
                <div class='card'>
                        
                        <div class='card-body'>
                            <h2 class='card-title'>$($ReportSub1)</h2>

                            <h2 class='card-title' style='margin-top:-10px'>$($ReportSub2)</h2>
                            
                            <p>$(Get-LocalizedString -Key 'ReportDetails')</p>"

        <#

               

        OUTPUT GENERATION / Summary cards

    #>

    $Output += "

                <div class='row p-3'>"

                if($InfoCount -gt 0)
                {
                    $Output += "
                    
                            <div class='col d-flex justify-content-center text-center'>
                                <div class='card text-white bg-secondary mb-3' style='width: 18em;'>
                                    <div class='card-header'><h6>$Informational</h6></div>
                                    <div class='card-body'>
                                    <h3>$($InfoCount)</h3>
                                    </div>
                                </div>
                            </div>
                    
                    "
                }

$Output +=        "<div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-warning mb-3' style='width: 18rem;'>
                        <div class='card-header'><h6>$Recommendation</h6></div>
                        <div class='card-body'>
                        <h3>$($RecommendationCount)</h3>
                        </div>
                    </div>
                </div>

                <div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-success mb-3' style='width: 18rem;'>
                        <div class='card-header'><h6>$OK</h6></div>
                        <div class='card-body'>
                        <h3>$($OKCount)</h3>
                        </div>
                    </div>
                </div>

            </div>"

    <#
    

    
                OUTPUT GENERATION / Config Health Index

    #>

    $Output += "
    <div class='card m-3'>

        <div class='card-body'>
            <div class='row'>
                <div class='col-sm-4 text-center align-self-center'>

                    <div class='progress' style='height: 40px'>
                        <div class='progress-bar progress-bar-striped bg-info' role='progressbar' style='width: $($Collection["CHI"])%;' aria-valuenow='$($Collection["CHI"])' aria-valuemin='0' aria-valuemax='100'><h2>$($Collection["CHI"]) %</h2></div>
                    </div>
                
                </div>
                <div class='col-sm-8'>
                    <h6>$(Get-LocalizedString -Key 'ConfigHealthIndex')</h6>                  
                    <p>$(Get-LocalizedString -Key 'ConfigHealthIndexDetails')</p>

                </div>
            </div>
                    
    </div>
  
    
    "

    <#
    
        OUTPUT GENERATION / Summary

    #>

    $Output += "
    <div class='card m-3'>
        <div class='card-header'>
            $Summary
        </div>
        <div class='card-body'>"


    $Output += "<h5>$(Get-LocalizedString -Key 'Areas')</h5>
            <table class='table table-borderless'>"
			
ForEach($Area in ($Checks | Where-Object {$_.Completed -eq $true} | Group-Object Area))
{
    $Pass = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Pass}).Count
    $Fail = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Fail}).Count
    $Info = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Informational}).Count

    # Normaliser le nom de la zone localisée et le mapper
    $LocalizedAreaName = $Area.Name.Trim().Normalize([System.Text.NormalizationForm]::FormD)
    
    if ($AreaMap.ContainsKey($LocalizedAreaName)) {
        $MappedAreaName = $AreaMap[$LocalizedAreaName]
    } else {
        # Si le nom de zone n'est pas trouvé, utiliser une valeur par défaut
        $MappedAreaName = "Default"
    }

    # Chercher l'icône correspondante
    $Icon = $AreaIcon[$MappedAreaName]
    If($Null -eq $Icon) { $Icon = $AreaIcon["Default"]}

    $Output += "
    <tr>
        <td width='20'><i class='$Icon'></i></td>
        <td><a href='#$($Area.Name)'>$($Area.Name)</a></td>
        <td align='right'>
            <span class='badge text-bg-secondary' style='padding:15px;text-align:center;width:40px;"; if($Info -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Info)</span>
            <span class='badge text-bg-warning' style='padding:15px;text-align:center;width:40px;"; if($Fail -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Fail)</span>
            <span class='badge text-bg-success' style='padding:15px;text-align:center;width:40px;"; if($Pass -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Pass)</span>
        </td>
    </tr>
    "
}







    $Output+="</table>
        </div>
    </div>
    "

    <#
    
    Keys
    
    #>

    $Output += "
    <div class='card m-3'>
        <div class='card-header'>
            $Legend
        </div>
        <div class='card-body'>
            <table class='table table-borderless'>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-dark'>
                            <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'Disabled')</span>
                            <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                        </div>
                    </td>
                    <td>
                        $(Get-LocalizedString -Key 'DisabledExplanation')
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-secondary'>
                            <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'DoesNotApply')</span>
                            <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                        </div>
                    </td>
                    <td>
                        $(Get-LocalizedString -Key 'DoesNotApplyExplanation')
                    </td>
                </tr>

                <tr>
                <td width='100'>
                    <div class='flex-row badge badge-pill text-bg-light'>
                    <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'ReadOnly')</span>
                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                    </div>
                </td>
                <td>
                    $(Get-LocalizedString -Key 'ReadOnlyExplanation')
                </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-info'>
                            <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'Preset')</span>
                        </div>
                    </td>
                    <td>
                        $(Get-LocalizedString -Key 'PresetExplanation')
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-info'>
                            <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'BuiltInProtectionPolicy')</span>
                        </div>
                    </td>
                    <td>
                        $(Get-LocalizedString -Key 'BuiltInProtectionPolicyExplanation')
                    </td>
                </tr>
            
                
            </table>
        </div>
    </div>"

    <#

        OUTPUT GENERATION / Zones

    #>

    ForEach ($Area in ($Checks | Where-Object {$_.Completed -eq $True} | Group-Object Area)) 
    {

        # Write the top of the card
        $Output += "
        <div class='card m-3'>
            <div class='card-header'>
            <a name='$($Area.Name)'>$($Area.Name)</a>
            </div>
            <div class='card-body'>"

        # Each check
        ForEach ($Check in ($Area.Group | Sort-Object Result -Descending)) 
        {

            $Output += "        
                <h5>$($Check.Name)</h5>"

                    If($Check.Result -eq [ORCAResult]::Pass) 
                    {
                        $CalloutType = "bd-callout-success"
                        $BadgeType = "text-bg-success"
                        $BadgeName = "OK"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.PassText
                    } 
                    ElseIf($Check.Result -eq [ORCAResult]::Informational) 
                    {
                        $CalloutType = "bd-callout-secondary"
                        $BadgeType = "text-bg-secondary"
                        $BadgeName = "Informational"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.FailRecommendation
                    }
                    Else 
                    {
                        $CalloutType = "bd-callout-warning"
                        $BadgeType = "text-bg-warning"
                        $BadgeName = "Improvement"
                        $Icon = "fas fa-thumbs-down"
                        $Title = $Check.FailRecommendation
                    }

#<span class="badge text-bg-primary">Primary</span>

                    $Output += "  
                    
                        <div class='bd-callout $($CalloutType) b-t-1 b-r-1 b-b-1 p-3'>
                            <div class='container-fluid'>
                                <div class='row'>
                                    <div class='col-1'><i class='$($Icon)'></i></div>
                                    <div class='col-8'><h5>$($Title)</h5></div>
                                    <div class='col' style='text-align:right'><h5><span class='badge $($BadgeType)'>$($BadgeName)</span></h5></div>
                                </div>"


                        if($Check.CheckFailed)
                        {
                                $Output +="
                                <div class='row p-3'>
                                    <div class='alert alert-danger' role='alert'>
                                    This check failed to run.  $($Check.CheckFailureReason)
                                    </div>
                                </div>"
                        }

                        if($Check.Importance) {

                                $Output +="
                                <div class='row p-3'>
                                    <div><p>$($Check.Importance)</p></div>
                                </div>"

                        }

                        If($Check.ExpandResults -eq $True) {

                            # We should expand the results by showing a table of Config Data and Items
                            $Output +="<h6>Effected objects</h6>
                            <div class='row pl-2 pt-3'>
                                <table class='table'>
                                    <thead class='border-bottom'>
                                        <tr>"

                            If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                            {
                                # Object, property, value checks need three columns
                                $Output +="
                                <th>$($Check.ObjectType)</th>
                                <th>$($Check.ItemName)</th>
                                <th>$($Check.DataType)</th>
                                "    
                            }
                            Else
                            {
                                $Output +="
                                <th>$($Check.ItemName)</th>
                                <th>$($Check.DataType)</th>
                                "     
                            }

                            $Output +="
                                            <th style='width:100px'></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            "

                            ForEach($o in $($Check.Config | Sort-Object Level))
                            {

                                $chiicon = ""
                                $chipill = ""
                                $chipts = [int]$($Check.ChiValue)

                                # Determine which to use based on AssessmentLevel
                                [ORCAResult]$AssessedResult = $o.ResultStandard

                                if($AssessmentLevel -eq [ORCAConfigLevel]::Strict)
                                {
                                    [ORCAResult]$AssessedResult = $o.ResultStrict
                                }
                                
                                if($AssessedResult -eq [ORCAResult]::Pass) 
                                {
                                    $oicon="fas fa-check-circle text-success"
                                    
                                    $LevelText = $o.Level.ToString()

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-plus"
                                        $chipill = "text-bg-success"
                                    }
                                }
                                ElseIf($AssessedResult -eq [ORCAResult]::Informational) 
                                {
                                    $oicon="fas fa-info-circle text-muted"
                                    $LevelText = "Informational"
                                }
                                Else
                                {
                                    $oicon="fas fa-times-circle text-danger"
                                    $LevelText = "Not Recommended"

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-minus"
                                        $chipill = "text-bg-danger"
                                    }
                                }

                                $Output += "
                                <tr>
                                "

                                # Multi line ConfigItem or ConfigData
                                If($o.ConfigItem -is [array] -or $o.ConfigItem -is [System.Collections.ArrayList])
                                {
                                    $ConfigItem = $o.ConfigItem -join "<br>"
                                }
                                else 
                                {
                                    $ConfigItem = $o.ConfigItem
                                }
                                If($o.ConfigData -is [array] -or $o.ConfigData -is [System.Collections.ArrayList])
                                {
                                    $ConfigData = $o.ConfigData -join "<br>"
                                }
                                else 
                                {
                                    $ConfigData = $o.ConfigData
                                }

                                $PolicyPills = "";

                                if($null -ne $o.ConfigPolicyGuid)
                                {
                                    # Get policy object
                                    $Policy = $Collection["PolicyStates"][$o.ConfigPolicyGuid]

                                    if($Policy.Preset)
                                    {
                                        $PolicyPills += "
                                            <div class='flex-row badge badge-pill text-bg-info'>
                                                <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'Preset') ($($Policy.PresetLevel.ToString()))</span>
                                            </div>"
                                    }

                                    if($Policy.BuiltIn)
                                    {
                                        $PolicyPills += "
                                            <div class='flex-row badge badge-pill text-bg-info'>
                                                <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'BuiltInProtectionPolicy')</span>
                                            </div>"
                                    }

                                }

                                If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                                {
                                    # Object, property, value checks need three columns
                                    $Output += "<td>$($o.Object)"

                                    if($o.ConfigDisabled -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-dark'>
                                                    <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'Disabled')</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigWontApply -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-secondary'>
                                                    <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'DoesNotApply')</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigReadonly -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'ReadOnly')</span>
                                                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }
                                    
                                    $Output += $PolicyPills
                                    
                                    $Output += "</td>"
                                        
                                    $Output += "<td>$($ConfigItem)</td>
                                        <td style='word-wrap: break-word;min-width: 50px;max-width: 350px;'>$($ConfigData)</td>
                                    "
                                }
                                Else 
                                {
                                    $Output += "<td>$($ConfigItem)"

                                    if($o.ConfigDisabled -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-dark'>
                                                    <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'Disabled')</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigWontApply -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-secondary'>
                                                    <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'DoesNotApply')</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigReadonly -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>$(Get-LocalizedString -Key 'ReadOnly')</span>
                                                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    $Output += $PolicyPills

                                    $Output += "</td>"

                                    $Output += "
                                        <td>$($ConfigData)</td>
                                    "
                                }

  
                                $Output += "
                                    <td style='text-align:right'>

                                    <div class='d-flex justify-content-end'>
                                "

                                if($($o.InfoText) -match "This is a Built-In/Default policy")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>$(Get-LocalizedString -Key 'MoreInfo')</u></abbr></p></div>"
                                    
                                }
                                elseif($($o.InfoText) -match "The policy is not enabled and will not apply")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>$(Get-LocalizedString -Key 'MoreInfo')</u></abbr></p></div>"                             
                                    
                                }
                                elseif($o.Level -eq [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>$(Get-LocalizedString -Key 'MoreInfo')</u></abbr></p></div>"
                              
                                }
                                else
                                {
                                    $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>$($LevelText)</span>
                                                    <span class='$($oicon)' style='vertical-align: middle;'></span>
                                                </div>"
                                

                                if($Check.ChiValue -ne [ORCACHI]::NotRated -and $o.Level -ne [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                                <div class='flex-row badge badge-pill $($chipill)'>
                                                    <span class='$($chiicon)' style='vertical-align: middle;'></span>
                                                    <span style='vertical-align: middle;'>$($chipts)</span>     
                                                </div>
                                    "
                                }            
                            }
                                $Output += "

                                    </div>

                                    </td>
                                </tr>
                                "
                            }

                            $Output +="
                                    </tbody>
                                </table>"
                                


                            $Output +="
                            </div>"

                        }

                        # If any links exist
                        If($Check.Links)
                        {
                            $Output += "
                            <table>"
                            ForEach($Link in $Check.Links.Keys) {
                                $Output += "
                                <tr>
                                <td style='width:40px'><i class='fas fa-external-link-alt'></i></td>
                                <td><a href='$($Check.Links[$Link])'>$Link</a></td>
                                <tr>
                                "
                            }
                            $Output += "
                            </table>
                            "
                        }

                        $Output += "
                            </div>
                        </div>  "
        }            

        # End the card
        $Output+=   "
            </div>
        </div>"

    }
    <#

        OUTPUT GENERATION / Footer

    #>

    $Output += "
            </main>
            </div>

            <footer class='app-footer'>
            <p><center>$(Get-LocalizedString -Key 'FooterMessage') <a href='https://www.cofomo.com/fr/'>CM365!</a><center></p>
            </footer>
        </body>"

    $Output += "</html>"


        # Write to file

        $OutputDir = $this.GetOutputDir();

        $ReportFileName = "ORCA-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').html"

        $OutputFile = "$OutputDir\$ReportFileName"

        $Output | Out-File -FilePath $OutputFile

        If($this.DisplayReport)
        {
            
            Invoke-Expression "&'$OutputFile'"
        }

        $this.Completed = $True
        $this.Result = $OutputFile

    }

    [string]GetOutputDir()
    {
        if($null -eq $this.OutputDirectory)
        {
            return $this.DefaultOutputDirectory
        }
        else 
        {
            return $this.OutputDirectory
        }
    }

    [string]getChartDataOverview($HistoricData)
    {

        $Output = "";
        $Output += "const data = {"
        $Output += "labels: ["
        # Build labels
        foreach($dataSet in $HistoricData)
        {
            $Output += "new Date('$($dataSet.ReportDate)'),"
        }

        # build dataset Recommendation OK InfoCount
        $Output += "],
        datasets: [{
            label: '$(Get-LocalizedString -Key 'Info')',
            borderColor: '#adb5bd',
            backgroundColor: '#adb5bd',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.InfoCount),"
            }

            $Output += "],
          },
          {
            label: '$(Get-LocalizedString -Key 'Recommendation')',
            borderColor: '#ffc107',
            backgroundColor: '#ffc107',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.Recommendation),"
            }

            $Output += "],
          },
          {
            label: '$(Get-LocalizedString -Key 'OK')',
            borderColor: '#198754',
            backgroundColor: '#198754',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.OK),"
            }

            $Output += "],
          }],
        };"
        return $Output += "`n"
    }

    [Object[]]GetHistoricData($Current,$Tenant)
    {
        $HistoricData = @($Current)


        # Get reports in outputdirectory
        try {

            $Path = $($this.GetOutputDir() + "\ORCA-$($Tenant)-*.html");
    
            $MatchingReports = Get-ChildItem $Path
            ForEach($MatchReport in $MatchingReports)
            {
                # Get the first line
                $FirstLines = Get-Content $MatchReport -First 2
                if($FirstLines[0] -like "<!-- checkjson*")
                {
                    # Get the underlying object
                    $DecodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($FirstLines[1]))
                    $Object = ConvertFrom-Json $DecodedText

                    if($Object.Tenant -eq $Tenant)
                    {
                        Write-Host "$(Get-Date) Output - HTML - Got historic data for tenant $($Tenant) in $($MatchReport.FullName)"
                        $HistoricData += $Object
                    }
                }
            }
        }
        catch {
            <#Do this if a terminating exception happens#>
        }

        return $HistoricData;
    }

}
