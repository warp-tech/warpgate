using CommandLine;

namespace AADJoin
{
    public class Options
    {
        [Option('j', "join-new-device", Required = false, HelpText = "Join new device to the Azure AD")]
        public bool JoinNewDevice { get; set; }

        [Option('c', "client-p2p-cert", Required = false, HelpText = "Obtain P2P certificate for the client authorization")]
        public bool ClientP2PCert { get; set; }

        [Option('s', "server-p2p-cert", Required = false, HelpText = "Obtain P2P certificate for the server authorization")]
        public bool ServerP2PCert { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Azure AD domain")]
        public string Domain { get; set; }

        [Option('u', "username", Required = true, HelpText = "User Azure AD username in FQDN format")]
        public string Username { get; set; }

        [Option('p', "password", Required = true, HelpText = "User password")]
        public string Password { get; set; }

        [Option('e', "existing-device", Required = false, HelpText = "Path to the PFX file with the device key + certificate")]
        public string DevicePfx { get; set; }

        [Option('f', "pfx-key-password", Required = false, HelpText = "PFX file password")]
        public string PfxPassword { get; set; }
    }
}
