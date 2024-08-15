# Load required modules
Import-Module .\ORCA.psm1

# Define the function to start the web server
function Start-WebServer {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://*:8080/")
    $listener.Start()
    Write-Output "Listening on http://localhost:8080/"

    while ($true) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        if ($request.Url.AbsolutePath -eq "/") {
            $html = Get-Content -Path .\index.html
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        } elseif ($request.Url.AbsolutePath -eq "/generate") {
            $language = $request.QueryString["language"]
            $reportPath = ".\report_${language}.xml"
            Get-CM365-Report -Language $language | Out-File -FilePath $reportPath

            $response.ContentType = "application/json"
            $jsonResponse = @{ reportPath = $reportPath } | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonResponse)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }

        $response.OutputStream.Close()
    }
}

# Start the web server
Start-WebServer
