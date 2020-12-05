using System.Text;
using Xunit;

namespace Knuth.Authentication.TOTP.Test
{
    public class Base32Tests
    {
        [Theory]
        [InlineData("a", "ME")]
        [InlineData("a", " M E ")]
        [InlineData("aa", "MFQQ")]
        [InlineData("aa", "-M-F-Q-Q-")]
        [InlineData("aaa", "MFQWC")]
        [InlineData("aaa", "_M_F_Q_W_C_")]
        [InlineData("aaaa", "MFQWCYI")]
        [InlineData("aaaa", "MFQWCYI=")]
        [InlineData("aoenuhta", "MFXWK3TVNB2GC")]
        [InlineData("aoenuhta", "MFXWK3TVNB2GC===")]
        [InlineData("aoenuhta", "\r\nMFXWK3\r\nTVNB2GC===")]
        [InlineData("123bnt0e", "GEZDGYTOOQYGK")]
        [InlineData("aonetbuac.rbau,nter", "MFXW4ZLUMJ2WCYZOOJRGC5JMNZ2GK4Q")]
        [InlineData("abcdabcdabcdabcd", "MFRGGZDBMJRWIYLCMNSGCYTDMQ")]
        // this is what many totp secred codes actually look like
        [InlineData("acbcodfget", "MFRW EY3P MRTG OZLU")]
        public void TestOne(string expected, string base32String)
        {
            var bytes = Base32.Decode(base32String);
            var result = Encoding.UTF8.GetString(bytes);
            Assert.Equal(expected, result);
        }
    }
}
