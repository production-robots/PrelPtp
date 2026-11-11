param([ValidateSet("Debug", "Release")][string]$Config = "Release")

msbuild "${PSScriptRoot}\PrelPtp.sln" "/p:Configuration=${Config}" "/p:Platform=x64"

