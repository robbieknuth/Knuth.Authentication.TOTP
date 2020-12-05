using System;

namespace Knuth.Authentication.TOTP
{
    public static class Base32
    {
        /// <summary>
        /// Decodes an RFC 4648 base32 encoded string. This is not a general purpose decoder. However
        /// it does ignore whitespace characters, '-', '=', and '_';
        /// </summary>
        /// <param name="base32String">The base32 encoded string.</param>
        /// <returns>The decoded bytes.</returns>
        /// <exception cref="FormatException">If the string is not a valid RFC 4648 string.</exception>
        public static byte[] Decode(string base32String)
        {
            if (base32String is null)
            {
                throw new ArgumentNullException(nameof(base32String));
            }

            var validBase32Chars = GetValidChars(base32String);
            return InnerDecode(validBase32Chars);
        }

        private static byte[] InnerDecode(ReadOnlySpan<char> base32Chars)
        {
            var bytes = new byte[base32Chars.Length * 5 / 8];

            var bitsPresent = 0;
            uint buffer = 0;
            var byteCount = 0;

            for (var i = 0; i < base32Chars.Length; i++)
            {
                var c = base32Chars[i];
                if (c is '=')
                {
                    continue;
                }

                var value = GetCharValue(c);
                buffer <<= 5;
                buffer |= value;
                bitsPresent += 5;
                if (bitsPresent >= 8)
                {
                    bytes[byteCount] = (byte)(buffer >> (bitsPresent - 8));
                    byteCount++;
                    bitsPresent -= 8;
                    buffer &= ~(uint.MaxValue << bitsPresent);
                }
            }

            return bytes;
        }

        private static Span<char> GetValidChars(string base32String)
        {
            var copiedKey = new char[base32String.Length];
            var charCount = 0;

            for (var i = 0; i < base32String.Length; i++)
            {
                var c = base32String[i];
                if (IsIgnoreCharacter(c))
                {
                    continue;
                }

                copiedKey[charCount] = c;
                charCount++;
            }

            return copiedKey.AsSpan(0, charCount);
        }

        private static bool IsIgnoreCharacter(char c)
        {
            return char.IsWhiteSpace(c) ||
                    c is '-' ||
                    c is '_' ||
                    c is '=';
        }

        private static byte GetCharValue(char c)
        {
            var value = char.ToLowerInvariant(c) switch
            {
                var x when x >= 'a' && x <= 'z' => x - 'a',
                var x when x >= '2' && x <= '7' => x - '2' + 26,
                _ => throw new FormatException($"Char {c} is not a valid base32 character according to RFC 4648.")
            };
            return (byte)value;
        }
    }
}
