using System;

namespace Knuth.Authentication.TOTP
{
    public sealed class TOTPResult
    {
        public string PreviousCode { get; }
        public string CurrentCode { get; }
        public string NextCode { get; }
        public TimeSpan ValidFor { get; }

        public TOTPResult(string previousCode, string currentCode, string nextCode, TimeSpan validFor)
        {
            this.PreviousCode = previousCode ?? throw new ArgumentNullException(nameof(previousCode));
            this.CurrentCode = currentCode ?? throw new ArgumentNullException(nameof(currentCode));
            this.NextCode = nextCode ?? throw new ArgumentNullException(nameof(nextCode));
            this.ValidFor = validFor;
        }

        public bool Matches(string input)
        {
            return
                string.Equals(this.PreviousCode, input) ||
                string.Equals(this.CurrentCode, input) ||
                string.Equals(this.NextCode, input);
        }
    }
}
