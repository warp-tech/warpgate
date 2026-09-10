using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AADJoin.Creds
{
    public class DeviceCreds
    {
        public string Id { get; set; }
        public RSA Key { get; set; }
        public X509Certificate Certificate { get; set; }

        public DeviceCreds(string id, RSA key, X509Certificate certificate)
        {
            Id = id;
            Key = key;
            Certificate = certificate;
        }

        public DeviceCreds(RSA key, X509Certificate certificate)
        {
            Console.WriteLine(certificate.Subject);
            Id = certificate.Subject.Split('=')[1];
            Key = key;
            Certificate = certificate;
        }

        public static DeviceCreds Empty()
        {
            return new DeviceCreds(null, null, null);
        }

        public static DeviceCreds FromPfx(string pfxPath, string password)
        {
            X509Certificate2 cert = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable);

            return new DeviceCreds(
                cert.GetRSAPrivateKey(),
                new X509Certificate(Convert.FromHexString(cert.GetRawCertDataString()))
            );
        }
    }
}
