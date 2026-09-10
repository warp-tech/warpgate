using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using CommandLine;
using AADJoin.Creds;

namespace AADJoin
{
    public class Program
    {
        static async Task Main(string[] args)
        {
            await Parser.Default.ParseArguments<Options>(args).WithParsedAsync(RunOptions);
        }

        static async Task RunOptions(Options opts)
        {
            var device = DeviceCreds.Empty();
            var user = new UserCreds(opts.Username, opts.Password, opts.Domain);

            // well-known client ids: https://github.com/Gerenios/AADInternals/blob/master/AccessToken_utils.ps1#L11
            // graph_api: 1b730954-1685-4b74-9bfd-dac224a7b894
            string clientId = "1b730954-1685-4b74-9bfd-dac224a7b894";

            await AzureAD.CheckUsername(opts.Username);
            var authResponse = await AzureAD.AzureAdAuthorize(clientId, user);

            if (opts.JoinNewDevice)
            {
                var tenantAuthResponse = await AzureAD.AzureTenantAuthorize(clientId, authResponse);
                device = await AzureAD.JoinDevice(opts.Domain, tenantAuthResponse);
            } else if (opts.DevicePfx != null)
            {
                Console.WriteLine("Trying to load device PFX file...");
                device = DeviceCreds.FromPfx(opts.DevicePfx, opts.PfxPassword);
            } else
            {
                Console.WriteLine("Error: No device information provided.");
                Environment.Exit(1);
            }

            if (opts.ServerP2PCert)
            {
                await AzureAD.ObtainServerP2PCertificate(user.Domain, authResponse.GetTenantId(), device);
            } else if (opts.ClientP2PCert)
            {
                await AzureAD.ObtainClientP2PCertificate(user, authResponse.GetTenantId(), device);
            } else
            {
                Console.WriteLine("Nothing left to do.");
            }
        }
    }
}
