using System;

namespace Knuth.Authentication.TOTP
{
    public sealed class TOTPOptions
    {
        public static readonly TOTPOptions Default = new ();

        public int Period { get; }
        public int Digits { get; }
        public int PriorPeriods { get; }
        public int FollowingPeriods { get; }

        public TOTPOptions(int digits = 6, int period = 30, int priorPeriods = 1, int followingPeriods = 1)
        {
            if (digits < 6 || digits > 8)
            {
                throw new ArgumentOutOfRangeException($"Number of digits must be in the range of >= 6 and <= 8. Request was for '{digits}'.");
            }
            this.Digits = digits;

            if (period < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(period), "Must be >= 1.");
            }
            this.Period = period;

            if (priorPeriods < 0 || priorPeriods > 10)
            {
                throw new ArgumentOutOfRangeException($"Up to 10 prior periods are supported. Request was for '{priorPeriods}'.");
            }
            this.PriorPeriods = priorPeriods;

            if (followingPeriods < 0 || followingPeriods > 10)
            {
                throw new ArgumentOutOfRangeException($"Up to 10 following periods are supported. Request was for '{followingPeriods}'.");
            }
            this.FollowingPeriods = followingPeriods;
        }
    }
}
