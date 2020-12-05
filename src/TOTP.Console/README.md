# Usage

## Console
TOTP.Console.exe <ALGORITHM> <KEY>

eg:

TOTP.Console.exe "sha1" "ABCDABCDABCDABCD"
TOTP.Console.exe "sha256" "ABCD ABCD ABCD ABCD"
TOTP.Console.exe "sha512" "ABCD-ABCD-ABCD-ABCD"

## Dotnet Run
dotnet run -- <ALGORITHM> <KEY>

eg:

dotnet run -- "sha1" "ABCDABCDABCDABCD"
dotnet run -- "sha256" "ABCD ABCD ABCD ABCD"
dotnet run -- "sha512" "ABCD-ABCD-ABCD-ABCD"

### Sample output
```
$> dotnet run -- "sha1" "ABCD ABCD ABCD ABCD"
Current: 229116 (Previous: 475214, Next: 666325)
    Next refresh in 10 seconds.
Current: 666325 (Previous: 229116, Next: 792774)
    Next refresh in 30 seconds.
```

