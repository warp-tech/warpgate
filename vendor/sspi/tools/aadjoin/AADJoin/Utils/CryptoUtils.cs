using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace AADJoin.Utils
{
    public class CryptoUtils
    {
        public static string PemCsrToFile(string rawCsr, Guid id)
        {
            return PemCsrToFile(rawCsr, id.ToString());
        }

        public static string PemCsrToFile(string rawCsr, string id)
        {
            var fileId = id + ".csr";

            string[] lines = { "-----BEGIN CERTIFICATE REQUEST-----", rawCsr, "-----END CERTIFICATE REQUEST-----" };
            File.WriteAllLines(fileId, lines);

            return fileId;
        }

        public static string PemCrtToFile(string rawCrt, Guid id)
        {
            return PemCrtToFile(rawCrt, id.ToString());
        }

        public static string PemCrtToFile(string rawCrt, string id)
        {
            var fileId = id + ".cer";

            string[] lines = { "-----BEGIN CERTIFICATE-----", rawCrt, "-----END CERTIFICATE-----" };
            File.WriteAllLines(fileId, lines);

            return fileId;
        }

        public static string RsaToPkcs8String(RSACng rsaKey, string password)
        {
            var bytes = rsaKey.ExportEncryptedPkcs8PrivateKey(
                password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 15)
            );

            return Convert.ToBase64String(bytes);
        }

        public static string RsaToPkcs8File(RSACng rsaKey, string password, string id)
        {
            var fileId = id + ".key";

            var bytes = rsaKey.ExportEncryptedPkcs8PrivateKey(
                password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 15)
            );
            string[] lines = {
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                Convert.ToBase64String(bytes),
                "-----END ENCRYPTED PRIVATE KEY-----"
            };
            File.WriteAllLines(fileId, lines);

            return fileId;
        }

        public static string PemCrtToPfxFile(string rawCrt, RSA privateKey, string id, string password)
        {
            var fileId = id + ".pfx";

            X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(rawCrt));
            X509Certificate2 pfxCert = cert.CopyWithPrivateKey(privateKey);

            byte[] pkcs12 = pfxCert.Export(X509ContentType.Pfx, password);

            File.WriteAllBytes(fileId, pkcs12);

            return fileId;
        }

    public static RSA Pkcs8ToRsa(string password, string content)
        {
            var rsa = RSA.Create();

            int bytesRead = 0;
            ReadOnlySpan<char> passwordSpan = password.AsSpan();
            ReadOnlySpan<byte> contentSpan = Convert.FromBase64String(content);
            rsa.ImportEncryptedPkcs8PrivateKey(passwordSpan, contentSpan, out bytesRead);

            return rsa;
        }

        public static byte[] FromBase64(string payload)
        {
            var data = payload.Replace("_", "/").Replace("-","+");

            while (data.Length % 4 != 0)
            {
                data += '=';
            }

            return Convert.FromBase64String(data);
        }

        public static byte[] DecryptSessionKeyFromJwe(string jwe, RSA key)
        {
            Console.WriteLine(jwe);
            var parsedJwe = jwe.Split('.');
            var cipher = FromBase64(parsedJwe[1]);
            Console.WriteLine(cipher.Length);

            return key.Decrypt(cipher, RSAEncryptionPadding.OaepSHA1);
        }

        public static byte[] ExtractContextFromJwe(string jwe)
        {
            var document = JsonDocument.Parse(FromBase64(jwe.Split('.')[0]));
            return FromBase64(document.RootElement.GetProperty("ctx").ToString());
        }

        public static byte[] DeriveSigningKey(byte[] sessionKey, byte[] context)
        {
            byte[] label = Encoding.UTF8.GetBytes("AzureAD-SecureConversation");

            List<byte> computeValue = new List<byte>();
            computeValue.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x01 });
            computeValue.AddRange(label);
            computeValue.Add(0x00);
            computeValue.AddRange(context);
            computeValue.AddRange(new byte[] { 0x00, 0x00, 0x01, 0x00 });

            HMACSHA256 hmac = new HMACSHA256(sessionKey);
            byte[] hmacOutput = hmac.ComputeHash(computeValue.ToArray());

            return hmacOutput;
        }

        public static string[] DecryptCeritficate(byte[] sessionKey, byte[] context, string jwe)
        {
            var parsedJwe = jwe.Split('.');
            var iv = FromBase64(parsedJwe[2]);
            var encData = FromBase64(parsedJwe[3]);
            var signingKey = DeriveSigningKey(sessionKey, context);

            var cryptoProvider = new AesCryptoServiceProvider();
            cryptoProvider.IV = iv;
            cryptoProvider.Key = signingKey;

            var buffer = new MemoryStream();
            var cryptoStream = new CryptoStream(buffer, cryptoProvider.CreateDecryptor(signingKey, iv), CryptoStreamMode.Write);

            cryptoStream.Write(encData, 0, encData.Count());
            cryptoStream.FlushFinalBlock();
            var decData = buffer.ToArray();

            cryptoStream.Dispose();
            cryptoProvider.Dispose();

            var document = JsonDocument.Parse(decData);
            var rdp = document.RootElement.GetProperty("x5c").ToString();
            var rdp_ca = document.RootElement.GetProperty("x5c_ca").ToString();

            return new[] { rdp, rdp_ca }; 
        }
    }
}
