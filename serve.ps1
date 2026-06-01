$port = 8000
$path = $PSScriptRoot

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$port/")
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()
Write-Host "Listening on http://127.0.0.1:$port/ and http://localhost:$port/"

function Send-Json($response, $data, $statusCode=200) {
    $response.ContentType = "application/json; charset=utf-8"
    $response.StatusCode = $statusCode
    $response.Headers.Add("Access-Control-Allow-Origin", "*")
    $response.Headers.Add("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
    $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    
    # Avoid ConvertTo-Json depth issues and properly encode
    $json = $data | ConvertTo-Json -Depth 10 -Compress
    if ([string]::IsNullOrEmpty($json)) { $json = "[]" }
    
    $content = [System.Text.Encoding]::UTF8.GetBytes($json)
    $response.ContentLength64 = $content.Length
    $response.OutputStream.Write($content, 0, $content.Length)
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        if ($request.HttpMethod -eq "OPTIONS") {
            $response.Headers.Add("Access-Control-Allow-Origin", "*")
            $response.Headers.Add("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
            $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
            $response.StatusCode = 204
            $response.Close()
            continue
        }

        $localPath = $request.Url.LocalPath.Replace('\', '/').TrimEnd('/')
        if ($localPath -eq "") { $localPath = "/index.html" }

        # Mock API Logic
        if ($localPath -eq "/api/health") {
            Send-Json $response @{ok=$true}
            $response.Close()
            continue
        }

        if ($localPath -eq "/api/auth/login") {
            $reqBody = ""
            if ($request.HasEntityBody) {
                $reader = New-Object System.IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $reqBody = $reader.ReadToEnd()
                $reader.Close()
            }
            $role = "student"
            $srn = "STUDENT123"
            if ($reqBody) {
                try {
                    $jsonBody = $reqBody | ConvertFrom-Json
                    if ($jsonBody.role) { $role = $jsonBody.role }
                    if ($jsonBody.srn) { $srn = $jsonBody.srn }
                } catch {}
            }

            $session = @{
                token = "mock-token-123"
                srn = $srn
                role = $role
                branch = "CSE"
                branchName = "Computer Science"
                batch = "2024"
                name = $srn
                photo = $null
            }
            Send-Json $response $session
            $response.Close()
            continue
        }

        if ($localPath.StartsWith("/api/content/")) {
            $parts = $localPath.Substring(13).Split('/')
            $collection = $parts[0].Split('?')[0]
            $dbPath = Join-Path $path "saptha_db.json"
            $items = @()
            $db = $null
            
            if (Test-Path $dbPath) {
                try {
                    $dbStr = Get-Content -Raw -Encoding UTF8 $dbPath
                    $db = $dbStr | ConvertFrom-Json
                    if ($null -ne $db.content.$collection) {
                        $items = @($db.content.$collection)
                    }
                } catch {
                    Write-Host "JSON Parse Error"
                }
            }

            if ($null -eq $db) {
                $db = @{ content = @{} }
            }

            if ($request.HttpMethod -eq "GET") {
                if ($request.Url.Query) {
                    $qScope = [regex]::Match($request.Url.Query, 'scope=([^&]+)').Groups[1].Value
                    if ($qScope) {
                        $qScope = [uri]::UnescapeDataString($qScope)
                        $items = @($items | Where-Object {
                            $itemScope = if ($_.data -and $_.data.PSObject.Properties.Name -contains 'scope') { $_.data.scope } else { $_.scope }
                            $itemScope -eq $qScope
                        })
                    }
                    $qBatch = [regex]::Match($request.Url.Query, 'batch=([^&]+)').Groups[1].Value
                    if ($qBatch) {
                        $qBatch = [uri]::UnescapeDataString($qBatch)
                        $items = @($items | Where-Object {
                            $itemBatch = if ($_.data -and $_.data.PSObject.Properties.Name -contains 'batch') { $_.data.batch } elseif ($_.batch) { $_.batch } else { "2024" }
                            $itemBatch -eq $qBatch
                        })
                    }
                }

                $json = $items | ConvertTo-Json -Depth 10 -Compress
                if ($items.Count -eq 1) { $json = "[$json]" }
                if ($items.Count -eq 0 -or [string]::IsNullOrEmpty($json)) { $json = "[]" }
                
                $response.ContentType = "application/json; charset=utf-8"
                $response.StatusCode = 200
                $response.Headers.Add("Access-Control-Allow-Origin", "*")
                $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
                $response.ContentLength64 = $contentBytes.Length
                $response.OutputStream.Write($contentBytes, 0, $contentBytes.Length)
            } elseif ($request.HttpMethod -eq "POST") {
                $reqBody = ""
                if ($request.HasEntityBody) {
                    $reader = New-Object System.IO.StreamReader($request.InputStream, $request.ContentEncoding)
                    $reqBody = $reader.ReadToEnd()
                    $reader.Close()
                }
                $newItem = @{
                    id = [guid]::NewGuid().ToString()
                    created_at = (Get-Date).ToString("o")
                    by = "Coordinator"
                }
                if ($reqBody) {
                    try {
                        $jsonBody = $reqBody | ConvertFrom-Json
                        if ($jsonBody.data) {
                            foreach ($prop in $jsonBody.data.PSObject.Properties) {
                                $newItem[$prop.Name] = $prop.Value
                            }
                        } else {
                            foreach ($prop in $jsonBody.PSObject.Properties) {
                                $newItem[$prop.Name] = $prop.Value
                            }
                        }
                    } catch {}
                }
                if (-not $newItem.batch) {
                    $newItem.batch = "2024"
                }
                $items += $newItem
                $db.content | Add-Member -MemberType NoteProperty -Name $collection -Value $items -Force
                $db | ConvertTo-Json -Depth 10 | Set-Content $dbPath -Encoding UTF8
                Send-Json $response $newItem
            } elseif ($request.HttpMethod -eq "DELETE") {
                if ($parts.Length -gt 1) {
                    $idToDelete = $parts[1]
                    $items = $items | Where-Object { $_.id -ne $idToDelete }
                    $db.content | Add-Member -MemberType NoteProperty -Name $collection -Value $items -Force
                    $db | ConvertTo-Json -Depth 10 | Set-Content $dbPath -Encoding UTF8
                }
                Send-Json $response @{ok=$true}
            } else {
                Send-Json $response @{ok=$true}
            }
            $response.Close()
            continue
        }

        # Static file handling
        $localPathWin = $localPath.Replace('/', '\')
        $filePath = $path + $localPathWin
        
        if (Test-Path $filePath -PathType Leaf) {
            $ext = [System.IO.Path]::GetExtension($filePath)
            switch ($ext) {
                ".html" { $response.ContentType = "text/html; charset=utf-8" }
                ".css"  { $response.ContentType = "text/css; charset=utf-8" }
                ".js"   { $response.ContentType = "application/javascript; charset=utf-8" }
                ".png"  { $response.ContentType = "image/png" }
                ".jpg"  { $response.ContentType = "image/jpeg" }
                ".json" { $response.ContentType = "application/json; charset=utf-8" }
                default { $response.ContentType = "application/octet-stream" }
            }
            
            try {
                $content = [System.IO.File]::ReadAllBytes($filePath)
                $response.ContentLength64 = $content.Length
                $response.OutputStream.Write($content, 0, $content.Length)
                $response.StatusCode = 200
            } catch {
                $response.StatusCode = 500
            }
        } else {
            $response.StatusCode = 404
        }
        $response.Close()
    }
} catch {
    Write-Host "Server error: $_"
} finally {
    $listener.Stop()
}
