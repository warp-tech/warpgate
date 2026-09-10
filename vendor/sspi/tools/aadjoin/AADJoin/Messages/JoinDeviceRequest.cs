using System;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using AADJoin.Utils;

namespace AADJoin.Messages
{
    public class JoinDeviceRequest
    {
        public class Csr
        {
            [JsonInclude]
            public string Type { get; set; }
            [JsonInclude]
            public string Data { get; set; }

            public Csr(string type, string data)
            {
                Type = type;
                Data = data;
            }
        }

        public class Attrs
        {
            [JsonInclude]
            public string ReuseDevice { get; set; }
            [JsonInclude]
            public string ReturnClientSid { get; set; }
            [JsonInclude]
            public string SharedDevice { get; set; }

            public Attrs(bool reuse, bool returnClientSid, bool sharedDevice)
            {
                ReuseDevice = reuse.ToString();
                ReturnClientSid = returnClientSid.ToString();
                SharedDevice = sharedDevice.ToString();
            }
        }

        public string TransportKey { get; set; }
        public int JoinType { get; set; }
        public string DeviceDisplayName { get; set; }
        public string OSVersion { get; set; }
        [JsonInclude]
        public Csr CertificateRequest { get; set; }
        public string TargetDomain { get; set; }
        public string DeviceType { get; set; }
        [JsonInclude]
        public Attrs Attributes { get; set; }

        public JoinDeviceRequest(string domain, RSACng key, Guid deviceId)
        {
            byte[] rsaPubKeyExport = key.Key.Export(CngKeyBlobFormat.GenericPublicBlob);
            TransportKey = Convert.ToBase64String(rsaPubKeyExport);

            // https://github.com/Gerenios/AADInternals/blob/master/PRT_Utils.ps1#L101
            // 0 = Azure AD join
            // 4 = Azure AD registered
            // 6 = Azure AD hybrid join
            JoinType = 0;

            var now = DateTime.Now;
            DeviceDisplayName = string.Format(
                "Test Device {0}{1}{2} {3}{4}{5}",
                now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second
            );

            OSVersion = "10.0.22000.978";

            var csr = new CertificateRequest("CN=7E980AD9-B86D-4306-9425-9AC066FB014A", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var rawCsr = Convert.ToBase64String(csr.CreateSigningRequest());
            CertificateRequest = new Csr("pkcs10", rawCsr);

            Console.WriteLine("The device certificate request (CSR) has been written into the file: {0}", CryptoUtils.PemCsrToFile(rawCsr, deviceId));

            TargetDomain = domain;

            DeviceType = "Windows";

            Attributes = new Attrs(true, true, false);
        }

        public override string ToString()
        {
            return JsonSerializer.Serialize(this);
        }
    }
}
