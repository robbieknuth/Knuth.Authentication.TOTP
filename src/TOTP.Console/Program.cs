using Knuth.Authentication.TOTP;
using Knuth.TOTP;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading;
using System.Threading.Tasks;

using SystemConsole = System.Console;

namespace TOTP.Console
{
    internal static class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length != 2)
            {
                SystemConsole.WriteLine("Usage: TOTP.exe <algorithm> <key>");
                return 1;
            }

            var totp = new ServiceCollection()
                .AddTOTP()
                .BuildServiceProvider()
                .GetRequiredService<ITOTPProvider>();

            using var cts = new CancellationTokenSource();
            SystemConsole.CancelKeyPress += (sender, eventArgs) =>
            {
                cts.Cancel();
                eventArgs.Cancel = true;
            };

            try
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    var codes = totp.GetCodes(args[0], args[1]);
                    SystemConsole.WriteLine($"Current: {codes.CurrentCode}");
                    SystemConsole.WriteLine($"    Next refresh in {(int)codes.ValidFor.TotalSeconds} seconds.");
                    await Task.Delay(codes.ValidFor, cts.Token);
                }
            }
            catch (OperationCanceledException) when (cts.Token.IsCancellationRequested) { }
            catch (AlgorithmNotFoundException e)
            {
                SystemConsole.Error.Write(e.Message);
                return 1;
            }
            catch (FormatException e)
            {
                SystemConsole.Error.WriteLine(e.Message);
                return 1;
            }
            catch (Exception e)
            {
                SystemConsole.Error.WriteLine("Unexpected exception encountered.");
                SystemConsole.Error.WriteLine(e);
                return 1;
            }

            return 0;
        }
    }
}
