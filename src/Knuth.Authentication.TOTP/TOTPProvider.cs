using Knuth.Authentication.TOTP;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Cryptography;

namespace Knuth.TOTP
{
    public sealed class TOTPProvider : ITOTPProvider
    {
        private readonly IDictionary<string, IHashAlgorithmProvider> hashAlgorithms;
        private readonly ISystemClock systemClock;
        private readonly DateTime unixEpoch;

        public static IEnumerable<IHashAlgorithmProvider> DefaultHashAlgorithms
        {
            get
            {
                return new List<IHashAlgorithmProvider>
                {
                    new HMACSHA1AlgorithmProvider(),
                    new HMACSHA256AlgorithmProvider(),
                    new HMACSHA512AlgorithmProvider()
                };
            }
        }

        /// <summary>
        /// Create a object capable of generating TOTP codes.
        /// </summary>
        /// <param name="systemClock">A way to control the system clock. Defaults to <see cref="SystemClock"/> if null.</param>
        /// <param name="hashAlgorithms">Creators for the hash algorithms to use. If null is set to <see cref="DefaultHashAlgorithms"/> </param>
        public TOTPProvider(IEnumerable<IHashAlgorithmProvider> hashAlgorithms = null, ISystemClock systemClock = null)
        {
            this.unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            this.systemClock = systemClock ?? new SystemClock();

            if (hashAlgorithms is null)
            {
                hashAlgorithms = DefaultHashAlgorithms;
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

        public ITOTPResult GetCodes(string hashAlgorithm, string key, TOTPOptions options = null)
            => this.GetCodes(hashAlgorithm, Base32.Decode(key), options);

        public ITOTPResult GetCodes(string hashAlgorithm, byte[] key, TOTPOptions options = null)
        {
            if (!this.hashAlgorithms.TryGetValue(hashAlgorithm, out var hashAlgorithmProvider))
            {
                throw new AlgorithmNotFoundException(hashAlgorithm);
            }

            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (options is null)
            {
                options = TOTPOptions.Default;
            }

            using var hmac = hashAlgorithmProvider.GetHash(key);
            var secondsSinceEpoch = (ulong)(this.systemClock.UtcNow - unixEpoch).TotalSeconds;
            var validFor = 30 - (secondsSinceEpoch % (uint)options.Period);
            var timePeriod = secondsSinceEpoch / (uint)options.Period;

            var currentCode = this.GetOneCode(hmac, timePeriod, options.Digits);
            var previousCodes = Enumerable.Range(0, options.PriorPeriods)
                .Select(x => this.GetOneCode(hmac, timePeriod - (ulong)x - 1, options.Digits));
            var followingCodes = Enumerable.Range(0, options.FollowingPeriods)
                .Select(x => this.GetOneCode(hmac, timePeriod + (ulong)x + 1, options.Digits));

            return new TOTPResult(currentCode, TimeSpan.FromSeconds(validFor), previousCodes, followingCodes);
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
            var code = this.CreateUInt32(
                hashDestination[offset],
                hashDestination[offset + 1],
                hashDestination[offset + 2],
                hashDestination[offset + 3]);
            return Format(code, digits);
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

        private static string Format(uint code, int digits)
        {
            return digits switch
            {
                6 => $"{code % 1000000:D6}",
                7 => $"{code % 10000000:D7}",
                8 => $"{code % 100000000:D8}",
                _ => throw new ArgumentOutOfRangeException($"Only number of digits >= 6 and <= 8 supported. Request was for '{digits}'.")
            };
        }
    }
}
