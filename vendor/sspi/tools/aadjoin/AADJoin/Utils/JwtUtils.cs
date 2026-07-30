using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using AADJoin.Creds;

namespace AADJoin.Utils
{
    public class JwtUtils
    {
        // The AAD cloud ap identifier. it will always be "38aa3b87-a06d-4817-b275–7a316988d93b"
        static string AadApIdentifier = "38aa3b87-a06d-4817-b275-7a316988d93b";

        public static string GenerateRdpCertificateRequestJwt(
            string nonce,
            string context,
            string username,
            string refreshToken,
            byte[] signingKey,
            RSA key
        )
        {
            var header = new JwtHeader();
            header.Add("alg", "HS256");
            header.Add("kdf_ver", "2");
            header.Add("ctx", context);

            var payload = new JwtPayload();
            payload.Add("iss", "aad:brokerplugin");
            payload.Add("grant_type", "refresh_token");
            payload.Add("aud", "login.microsoftonline.com");
            payload.Add("request_nonce", nonce);
            payload.Add("scope", "openid aza ugs");
            payload.Add("refresh_token", refreshToken);
            payload.Add("client_id", AadApIdentifier);
            payload.Add("cert_token_use", "user_cert");
            payload.Add("csr_type", "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10");

            var csr = new CertificateRequest(string.Format("CN = {0}", username), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var rawCsr = Convert.ToBase64String(csr.CreateSigningRequest());
            payload.Add("csr", rawCsr);

            payload.Add("win_ver", "10.0.22000.653");

            var dataToSign = string.Format("{0}.{1}", header.Base64UrlEncode(), payload.Base64UrlEncode());

            HMACSHA256 hmac = new HMACSHA256(signingKey);
            byte[] hmacOutput = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));

            var finalJwt = string.Format("{0}.{1}", dataToSign, Convert.ToBase64String(hmacOutput).Split('=')[0]);
            Console.WriteLine(finalJwt);

            return finalJwt;
        }

        public static string GenerateFRequestJwt(string nonce, DeviceCreds device, UserCreds user)
        {
            var header = new JwtHeader();
            header.Add("alg", "RS256");
            header.Add("typ", "JWT");
            header.Add("x5c", Convert.ToBase64String(device.Certificate.Export(X509ContentType.Cert)));
            header.Add("kdf_ver", "2");

            var payload = new JwtPayload();
            payload.Add("client_id", AadApIdentifier);
            payload.Add("request_nonce", nonce);
            payload.Add("scope", "openid aza ugs");
            payload.Add("win_ver", "10.0.22000.653");
            payload.Add("grant_type", "password");
            payload.Add("username", user.Username);
            payload.Add("password", user.Password);

            var dataToSign = string.Format("{0}.{1}", header.Base64UrlEncode(), payload.Base64UrlEncode());

            var signature = device.Key.SignData(Encoding.ASCII.GetBytes(dataToSign), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var finalJwt = string.Format("{0}.{1}", dataToSign, Convert.ToBase64String(signature).Split('=')[0]);
            Console.WriteLine(finalJwt);

            return finalJwt;
        }

        public static string GenerateP2PRequestJwt(string nonce, DeviceCreds device, string dnsName)
        {
            var header = new JwtHeader();
            header.Add("alg", "RS256");
            header.Add("typ", "JWT");
            header.Add("x5c", Convert.ToBase64String(device.Certificate.Export(X509ContentType.Cert)));

            var payload = new JwtPayload();
            payload.Add("client_id", AadApIdentifier);
            payload.Add("request_nonce", nonce);
            payload.Add("win_ver", "10.0.18363.0");
            payload.Add("grant_type", "device_auth");
            payload.Add("cert_token_use", "device_cert");
            payload.Add("csr_type", "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10");

            var csr = new CertificateRequest(device.Certificate.Subject, device.Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var rawCsr = Convert.ToBase64String(csr.CreateSigningRequest());
            payload.Add("csr", rawCsr);

            payload.Add("netbios_name", dnsName);
            payload.Add("dns_names", new string[] { dnsName });

            var dataToSign = string.Format("{0}.{1}", header.Base64UrlEncode(), payload.Base64UrlEncode());

            var signature = device.Key.SignData(Encoding.ASCII.GetBytes(dataToSign), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var finalJwt = string.Format("{0}.{1}", dataToSign, Convert.ToBase64String(signature).Split('=')[0]);
            Console.WriteLine(finalJwt);

            return finalJwt;
        }
    }
}
