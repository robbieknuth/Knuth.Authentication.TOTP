using System.Security.Cryptography;

namespace Knuth.Authentication.TOTP
{
    public interface IHashAlgorithmProvider
    {
        string Moniker { get; }
        HashAlgorithm GetHash(byte[] key);
    }
}
