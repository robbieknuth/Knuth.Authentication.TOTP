using System;

namespace Knuth.TOTP
{
    internal static class TenToThe
    {
        private static readonly int[] Powers = new[]
        {
            1000000,
            10000000,
            100000000
        };

        public static int PowerOf(int exponent)
        {
            if (exponent < 6 || exponent > 8)
            {
                throw new ArgumentOutOfRangeException("Only powers >= 6 and <= 8 supported.");
            }

            return Powers[exponent - 6];
        }
    }
}
