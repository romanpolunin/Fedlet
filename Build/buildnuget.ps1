Remove-Item -Path .\lib -Recurse -Force
Remove-Item -Path .\NOTICES.txt -Force
Remove-Item -Path .\LICENSE.txt -Force
Remove-Item -Path .\CHANGES.txt -Force
Remove-Item -Path .\README -Force

md lib\Net462
Copy-Item ..\Fedlet\bin\Release\Fedlet.dll .\lib\Net462
Copy-Item ..\Fedlet\bin\Release\Fedlet.xml .\lib\Net462
Copy-Item ..\Fedlet\bin\Release\Fedlet.pdb .\lib\Net462

Copy-Item ..\NOTICES.txt .\
Copy-Item ..\LICENSE.txt .\
Copy-Item ..\CHANGES.txt .\
Copy-Item ..\README .\

..\..\Nuget\nuget.exe pack Fedlet.1.0.nuspec