using Knuth.Authentication.TOTP;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Knuth.TOTP
{
    public sealed class TOTPProvider : ITOTPProvider
    {
        private readonly IDictionary<string, IHashAlgorithmProvider> hashAlgorithms;
        private readonly ISystemClock systemClock;
        private readonly DateTime unixEpoch;

        /// <summary>
        /// Create a object capable of generating TOTP codes.
        /// </summary>
        /// <param name="systemClock">A way to control the system clock. Defaults to <see cref="SystemClock"/> if null.</param>
        /// <param name="hashAlgorithms">Creators for the hash algorithms to use. There cannot be nulls or duplicate entries.</param>
        public TOTPProvider(IEnumerable<IHashAlgorithmProvider> hashAlgorithms, ISystemClock systemClock = null)
        {
            this.unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            this.systemClock = systemClock ?? new SystemClock();

            if (hashAlgorithms is null)
            {
                throw new ArgumentNullException(nameof(hashAlgorithms));
            }

            this.hashAlgorithms = new Dictionary<string, IHashAlgorithmProvider>(StringComparer.OrdinalIgnoreCase);
            foreach (var hashAlgorithm in hashAlgorithms)
            {
                if (hashAlgorithm is null)
                {
                    throw new ArgumentException("Hash algorithms cannot contain null elements.", nameof(hashAlgorithms));
                }

                var key = hashAlgorithm.Moniker;
                if (key is null)
                {
                    throw new ArgumentException("Hash algorithm cannot have a null key.", nameof(hashAlgorithms));
                }

                if (this.hashAlgorithms.ContainsKey(hashAlgorithm.Moniker))
                {
                    throw new ArgumentException($"Detected two hash algorithms with the key '{hashAlgorithm.Moniker}'.");
                }

                this.hashAlgorithms[hashAlgorithm.Moniker] = hashAlgorithm;
            }
        }

        /// <inheritdoc />
        public TOTPResult GetCodes(string hashAlgorithm, string key, int digits = 6, int period = 30)
            => this.GetCodes(hashAlgorithm, Base32.Decode(key), digits, period);

        /// <inheritdoc />
        public TOTPResult GetCodes(string hashAlgorithm, byte[] key, int digits = 6, int period = 30)
        {
            if (!this.hashAlgorithms.TryGetValue(hashAlgorithm, out var hashAlgorithmProvider))
            {
                throw new AlgorithmNotFoundException(hashAlgorithm);
            }

            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (digits < 6 || digits > 8)
            {
                throw new ArgumentOutOfRangeException(nameof(digits), "Must be >= 6 and <= 8.");
            }

            if (period < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(period), "Must be >= 1.");
            }

            using var hmac = hashAlgorithmProvider.GetHash(key);
            var secondsSinceEpoch = (ulong)(this.systemClock.UtcNow - unixEpoch).TotalSeconds;
            var validFor = 30 - (secondsSinceEpoch % (uint)period);

            var timePeriod = secondsSinceEpoch/ (uint)period;
            return new TOTPResult(
                this.GetOneCode(hmac, timePeriod - 1, digits),
                this.GetOneCode(hmac, timePeriod, digits),
                this.GetOneCode(hmac, timePeriod + 1, digits),
                TimeSpan.FromSeconds(validFor));
        }

        private string GetOneCode(HashAlgorithm hashAlgorithm, ulong timePeriod, int digits)
        {
            var timeStepBytes = BitConverter.GetBytes(timePeriod);
            if (BitConverter.IsLittleEndian)
            {
                Span<byte> reverso = timeStepBytes;
                reverso.Reverse();
            }

            var hashDestination = hashAlgorithm.ComputeHash(timeStepBytes);

            var offset = hashDestination[hashDestination.Length - 1] & 0x0F;
            var result = this.CreateUInt32(
                hashDestination[offset],
                hashDestination[offset + 1],
                hashDestination[offset + 2],
                hashDestination[offset + 3]);
            var digitizedHashRegion = result % TenToThe.PowerOf(digits);
            return string.Format($"{{0:D{digits}}}", digitizedHashRegion);
        }

        private uint CreateUInt32(uint one, uint two, uint three, uint four)
        {
            // RFC 4226:
            // We treat the dynamic binary code as a 31-bit, unsigned, big-endian
            // integer; the first byte is masked with a 0x7f.
            //
            // obviously. so that's why that stray 0x7f is there. probably because some languages
            // don't have a UInt32.
            return ((one & 0x7f) << 24) | (two << 16) | (three <<  8) | four;
        }
    }
}
