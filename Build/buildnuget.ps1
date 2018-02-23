Remove-Item -Path .\lib -Recurse -Force
Remove-Item -Path .\NOTICES.txt -Force
Remove-Item -Path .\LICENSE.txt -Force
Remove-Item -Path .\CHANGES.txt -Force
Remove-Item -Path .\README -Force

md lib\netstandard2.0
Copy-Item ..\Fedlet\bin\Release\Fedlet.dll .\lib\netstandard2.0
Copy-Item ..\Fedlet\bin\Release\Fedlet.xml .\lib\netstandard2.0
Copy-Item ..\Fedlet\bin\Release\Fedlet.pdb .\lib\netstandard2.0

Copy-Item ..\NOTICES.txt .\
Copy-Item ..\LICENSE.txt .\
Copy-Item ..\CHANGES.txt .\
Copy-Item ..\README .\

..\..\Nuget\nuget.exe pack Fedlet.2.0.nuspec