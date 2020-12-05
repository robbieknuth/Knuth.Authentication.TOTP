# Knuth.Authentication.TOTP
A dotnet implementation of Time-based One-time passwords (aka TOTP). This implementation attempts to conform to RFC 6238, and has been tested against
- RFC 6238 example tests
- Google Authenticator
- Microsoft Authenticator
- [Dan Hersam's TOTP Generator](https://totp.danhersam.com/)

Primarily targetted at adding TOTPs to ASP.NET Core applications, however of course it will work wherever. The library targets `netstandard2.0` for maximum compatibility.

# Caveats
- No brute force protection

  This library is completely stateless and does not implement any kind of brute force detection.
  
- Secret handling

  This library does not attempt to wipe TOTP secrets from memory. If someone has access to a memory dump or a debugger on your process, you're already toast.
  
- Secret generation

  This library does not generate TOTP secrets. Use your favorite cryptographically secure random number generator.

# Usage
This library is designed primarily with dependency injection in mind. However it may be used without DI as well, though it may feel a little clunky that way.

Base32 encoding is *not* required to use this library. Ultimately the hash algorithm consumes *bytes*. Base32 is often used to present these bytes to the user and thus is given an overload on `ITOTPProvider` for convenience. The examples in RFC 6238 uses HEX for the keys. In that case, simply use the overload where `key` is a byte array.

Three algorithms are built in out of the box: SHA1, SHA256, and SHA512. Currently, replacing the default implementation is not supported. Adding new algorithms is supported, see
**Adding an algorithm** below.

## Example - Console
You can see the example console project
[TOTP.Console](https://github.com/robbieknuth/Knuth.Authentication.TOTP/tree/main/src/TOTP.Console) for very simple usage. This is effectively the same functionality as a your favorite 2FA app, minus the QR code scanner.

## Example - Validator
This example assumes that you have a way to store the TOTP secrets elsewhere. This will be referred to as the `ISecretProvider`

### Add to DI container
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddTOTP();
}
```

### Consume (pseudo code-ish)
```csharp
public sealed class MyValidator
{
    private readonly ITOTPProvider totp;
    private ISecretProvider secretProvider;
    
    public MyValidator(ITOTPProvider totp, ISecretProvider secretProvider)
    {
        this.totp = totp;
        this.secretProvider = secretProvider;
    }
    
    public async Task ValidateTOTP(string incomingCode, IUser user, CancellationToken cancellationToken = default)
    {
        var secret = await this.secretProvider.GetTOTPSecretAsync(user, cancellationToken);
        // this overload assumes secret is a valid RFC 4648 base32 encoded string.
        var codes = this.totp.GetCodes("sha1", secret);
        if (!codes.Matches(incomingCode))
        {
            throw new NotAuthorizedException();
        }
    }
}
```

## Adding an algorithm
The library implements default providers for SHA1, SHA256, and SHA512, SHA1 being the default for most apps (for better or worse). Adding a hash algorithm with DI is straight forward.

### Implement IHashAlgorithmProvider
```csharp
public sealed class MyMagicAlgorithmProvider : IHashAlgorithmProvider
{
    public const string MyMagicMoniker = "magic";
    
    public string Moniker => MyMagicMoniker;
    
    public HashAlgorithm GetHash(byte[] key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        return new MyMagicHashAlgorithm(key);
    }
}
```

### Register with the DI container
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services
        .AddTOTP()
        .AddSingleton<IHashAlgorithmProvider, MyMagicAlgorithmProvider>();
}
```

### Consume at some point
The `hashAlgorithm` parameter of `ITOTPProvider.GetCodes` simply is a key into a dictionary of algorithm creators. So just pass in whatever moniker you used to have the `ITOTPProvider` use your algorithm.
```csharp
var codes = this.totp.GetCodes(MyMagicAlgorithmProvider.MyMagicMoniker, secret);
```
