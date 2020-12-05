using System;
using System.Collections.Generic;

namespace Knuth.Authentication.TOTP
{
    internal sealed class TOTPResult : ITOTPResult
    {
        private readonly ISet<string> previousCodes;
        private readonly ISet<string> followingCodes;

        public string CurrentCode { get; }
        public TimeSpan ValidFor { get; }

        public TOTPResult(string currentCode, TimeSpan validFor, IEnumerable<string> previousCodes, IEnumerable<string> followingCodes)
        {
            this.CurrentCode = currentCode;
            this.previousCodes = new HashSet<string>(previousCodes);
            this.followingCodes = new HashSet<string>(followingCodes);
            this.ValidFor = validFor;
        }

        public bool Matches(string input)
        {
            return this.CurrentCode == input ||
                this.previousCodes.Contains(input) ||
                this.followingCodes.Contains(input);
        }
    }
}
