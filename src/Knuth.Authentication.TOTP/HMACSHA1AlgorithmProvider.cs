using System;
using System.Security.Cryptography;

namespace Knuth.Authentication.TOTP
{
    public sealed class HMACSHA1AlgorithmProvider : IHashAlgorithmProvider
    {
        public const string SHA1Moniker = "sha1";

        public string Moniker => SHA1Moniker;

        public HashAlgorithm GetHash(byte[] key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return new HMACSHA1(key);
        }
    }
}
