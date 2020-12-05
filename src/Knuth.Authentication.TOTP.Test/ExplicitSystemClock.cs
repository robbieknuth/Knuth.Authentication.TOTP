using System;
using System.Globalization;

namespace Knuth.Authentication.TOTP.Test
{
    internal sealed class ExplicitSystemClock : ISystemClock
    {
        private readonly DateTime dateTime;

        public ExplicitSystemClock(string dateTime)
        {
            this.dateTime = DateTime.Parse(dateTime, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
        }

        public DateTime UtcNow => this.dateTime;
    }
}
