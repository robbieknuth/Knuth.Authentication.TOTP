using System;
using System.Security.Cryptography;

namespace Knuth.Authentication.TOTP
{
    public sealed class HMACSHA512AlgorithmProvider : IHashAlgorithmProvider
    {
        public const string SHA512Moniker = "sha512";

        public string Moniker => SHA512Moniker;

        public HashAlgorithm GetHash(byte[] key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return new HMACSHA512(key);
        }
    }
}
