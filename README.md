# Problem
You need to build strong named assembly. But your references has references to not signed dll too. Then for fix them you need to fix them references too.

## Solution
Add as Pre-build events to first project of build order. Solution (right click) -> Project Build Order:
> $(SolutionDir)tools\SignDllTool.exe /dir:$(SolutionDir)packages /in:FluentValidation[\.\d]+\\lib\\Net45\\FluentValidation\.dll;MongoDB\.Bson;RestSharp[\.\d]+\\lib\\net4[\d]*\\;DotNetZip /key:$(SolutionDir)sign.snk

Where SignDllTool app for resign dlls with your snk. Solution based on [Signing an Unsigned Assembly](http://buffered.io/posts/net-fu-signing-an-unsigned-assembly-without-delay-signing/)
And argument /in:Regex - regular expression separated by ; for resolve path to dlls in argument /dir:

snk must be with private key without protection (password). Please see https://github.com/aarnott/pfx2Snk

## make snk
```sh
makecert.exe -pe -n "CN=SignDllTool.Tests" -eku 1.3.6.1.5.5.7.3.3 -a sha1 -r -sv sign.pvk sign.cer
pvk2pfx.exe -pvk sign.pvk -pi 123 -spc sign.cert -pfx sign.pfx
pfx2snk sign.pfx 123 sign.snk
```

## External
* [Windows SDK](http://www.microsoft.com/en-us/download/details.aspx?id=8442)
* https://github.com/aarnott/pfx2Snk
* [Signing an Unsigned Assembly](http://buffered.io/posts/net-fu-signing-an-unsigned-assembly-without-delay-signing/)