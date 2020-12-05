using System;
using System.Security.Cryptography;

namespace Knuth.Authentication.TOTP
{
    public sealed class HMACSHA256AlgorithmProvider : IHashAlgorithmProvider
    {
        public const string SHA256Moniker = "sha256";

        public string Moniker => SHA256Moniker;

        public HashAlgorithm GetHash(byte[] key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return new HMACSHA256(key);
        }
    }
}
