$env:Path = $env:Path + ";${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$installationPath = vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath

# Get enviroment variables from developer command prompt
# See: https://github.com/Microsoft/vswhere/wiki/Start-Developer-Command-Prompt
if ($installationPath -and (test-path "$installationPath\Common7\Tools\vsdevcmd.bat"))
{
  & "${env:COMSPEC}" /s /c "`"$installationPath\Common7\Tools\vsdevcmd.bat`" -no_logo && set" | foreach-object {
    $name, $value = $_ -split '=', 2
    set-content env:\"$name" $value
  }
}

msbuild /nologo /verbosity:minimal /maxcpucount /p:Configuration=Release /p:Platform=x64 /target:Rebuild