using AADJoin.Creds;
using AADJoin.Messages;
using AADJoin.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AADJoin
{
    internal class AzureAD {
        /// <summary>
        /// Checks if the account associated with provided username exists and active
        /// </summary>
        /// <param name="username">Account username</param>
        /// <returns></returns>
        public static async Task CheckUsername(string username)
        {
            Console.WriteLine("Start {0} username checking...", username);
            var url = String.Format("https://login.microsoftonline.com/common/userrealm/{0}?api-version=1.0", username);

            var httpClient = new HttpClient();

            var response = await httpClient.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine("Error. Status code: {0}. Body:", response.StatusCode);
                Console.WriteLine(content);
                Environment.Exit(1);
            }

            Console.WriteLine(content);
            Console.WriteLine("User exist and active");
        }

        /// <summary>
        /// Performs basic authorization in the Azure AD using account username and password.
        /// It's just account authorization and not related to any tenant.
        /// </summary>
        /// <param name="clientId">client id</param>
        /// <param name="user">Account credentials</param>
        /// <returns>AuthResponse object</returns>
        public static async Task<AuthResponse> AzureAdAuthorize(string clientId, UserCreds user)
        {
            Console.WriteLine("Start Azure AD authorization...");

            var url = "https://login.microsoftonline.com//common/oauth2/token";

            var httpClient = new HttpClient();

            var form = new Dictionary<string, string>();
            form.Add("grant_type", "password");
            form.Add("password", user.Password);
            form.Add("client_id", clientId);
            form.Add("username", user.Username);
            form.Add("resource", "https://graph.windows.net");
            form.Add("scope", "openid");

            var response = await httpClient.PostAsync(url, new FormUrlEncodedContent(form));
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", response.StatusCode));
                Console.WriteLine(content);
                Environment.Exit(1);
            }

            Console.WriteLine(content);
            var authResponse = JsonSerializer.Deserialize<AuthResponse>(content);
            Console.WriteLine("Azure AD authorization succeeded!");

            return authResponse;
        }

        /// <summary>
        /// Performs user authorization in the tenant using previously obtained refresh token.
        /// </summary>
        /// <param name="clientId">client id</param>
        /// <param name="authResponse">AuthResponse object returned from the AzureADAuthorize method</param>
        /// <returns>TenantAuthResponse object</returns>
        public static async Task<TenantAuthResponse> AzureTenantAuthorize(string clientId, AuthResponse authResponse)
        {
            Console.WriteLine("Start Azure Tenant authorization...");

            var url = string.Format("https://login.microsoftonline.com/{0}/oauth2/token", authResponse.GetTenantId());

            var httpClient = new HttpClient();

            var form = new Dictionary<string, string>();
            form.Add("scope", "openid");
            form.Add("grant_type", "refresh_token");

            // https://github.com/Gerenios/AADInternals/blob/master/AccessToken.ps1#L1864
            // 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 means urn:ms-drs:enterpriseregistration.windows.net
            // More UUIDs: https://www.rickvanrousselt.com/blog/azure-default-service-principals-reference-table/
            form.Add("resource", "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9");

            form.Add("client_id", clientId);
            form.Add("refresh_token", authResponse.refresh_token);

            var response = await httpClient.PostAsync(url, new FormUrlEncodedContent(form));
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", response.StatusCode));
                Console.WriteLine(content);
                Environment.Exit(1);
            }

            Console.WriteLine(content);
            var tenantAuthResponse = TenantAuthResponse.FromString(content);
            Console.WriteLine("Azure Tenant authorization succeeded!");

            return tenantAuthResponse;
        }

        /// <summary>
        /// Joins new device to the Azure AD. Automatically creates new device key/certificate, and id. The device id is
        /// a randomly generated UUID. The private key password is the device id.
        /// Saves them in corresponding files:
        /// * `{device_id}.key` - the device private key; {device_id} is a password from the key;
        /// * `{random_id}.csr` - the device certificate request that has been used to obtain the device certificate;
        /// * `{device_id}.cer` - the device certificate;
        /// </summary>
        /// <param name="domain">Azure AD domain</param>
        /// <param name="tenantAuthResponse">TenantAuthResponse object returned from the AzureTenantAuthorize method</param>
        /// <returns>Device creds object</returns>
        public static async Task<DeviceCreds> JoinDevice(string domain, TenantAuthResponse tenantAuthResponse)
        {
            Console.WriteLine("Start device joining...");

            var url = "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0";

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tenantAuthResponse.access_token);

            var deviceId = Guid.NewGuid();
            // minimal key size = 2048
            var deviceKey = new RSACng(2048);

            var joinDeviceRequest = new JoinDeviceRequest(domain, deviceKey, deviceId);

            var data = new StringContent(joinDeviceRequest.ToString());
            data.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var response = await httpClient.PostAsync(url, data);
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", response.StatusCode));
                Console.WriteLine(content);
                Environment.Exit(1);
            }

            Console.WriteLine(content);
            var joinDeviceResponse = JoinDeviceResponse.FromString(content);

            var certificate = new X509Certificate(Convert.FromBase64String(joinDeviceResponse.Certificate.RawBody));
            var device = new DeviceCreds(deviceKey, certificate);

            Console.WriteLine("The device transport key password: {0}", device.Id);
            Console.WriteLine(
                "The device transport key (PKCS8) has been written into the file: {0}",
                CryptoUtils.RsaToPkcs8File(deviceKey, device.Id, device.Id)
            );

            Console.WriteLine(
                "The device certificate (.pfx) has been written into the file: {0}",
                CryptoUtils.PemCrtToPfxFile(joinDeviceResponse.Certificate.RawBody, deviceKey, device.Id, device.Id)
            );

            Console.WriteLine(
                "The device certificate (.cer) has been written into the file: {0}",
                CryptoUtils.PemCrtToFile(joinDeviceResponse.Certificate.RawBody, device.Id)
            );

            Console.WriteLine("Device joining succeeded!");

            return device;
        }

        /// <summary>
        /// Requests nonce from the Azure AD tenant.
        /// </summary>
        /// <param name="tenantId">Tenant UUID</param>
        /// <returns>Base64 encoded nonce</returns>
        private static async Task<string> RequestNonce(string tenantId)
        {
            Console.WriteLine("Start obtaining nonce...");

            var httpClient = new HttpClient();

            var url = string.Format("https://login.microsoftonline.com/{0}/oauth2/token", tenantId);

            var nonceForm = new Dictionary<string, string>();
            nonceForm.Add("grant_type", "srv_challenge");

            var nonceResponse = await httpClient.PostAsync(url, new FormUrlEncodedContent(nonceForm));
            var nonceContent = await nonceResponse.Content.ReadAsStringAsync();

            if (nonceResponse.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", nonceResponse.StatusCode));
                Console.WriteLine(nonceContent);
                Environment.Exit(1);
            }

            Console.WriteLine(nonceContent);

            var document = JsonDocument.Parse(nonceContent);
            var nonce = document.RootElement.GetProperty("Nonce");

            return nonce.ToString();
        }

        /// <summary>
        /// Obtains refresh and access token with the TGT.
        /// </summary>
        /// <param name="user">Account credentials</param>
        /// <param name="tenantId">Tenant id</param>
        /// <param name="nonce">Previously obtained nonce</param>
        /// <param name="device">Device creds (private key and certificate)</param>
        /// <returns>JSON response from AzureAD as string</returns>
        private static async Task<string> TokenWithTgt(
            UserCreds user,
            string tenantId,
            string nonce,
            DeviceCreds device
        )
        {
            Console.WriteLine("Start TokenWithTGT...");

            var httpClient = new HttpClient();

            var url = string.Format("https://login.microsoftonline.com/{0}/oauth2/token", tenantId);

            var certForm = new Dictionary<string, string>();
            certForm.Add("request", JwtUtils.GenerateFRequestJwt(
                nonce,
                device,
                user
            ));
            certForm.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            certForm.Add("client_info", "1");
            certForm.Add("tgt", "true");
            certForm.Add("windows_api_version", "2.2");

            var response = await httpClient.PostAsync(url, new FormUrlEncodedContent(certForm));
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", response.StatusCode));
                Console.WriteLine(content);

                Environment.Exit(1);
            }

            Console.WriteLine(content);
            return content;
        }

        /// <summary>
        /// Checks if the provided domain exists and active
        /// </summary>
        /// <param name="domain">AzureAD domain</param>
        /// <returns></returns>
        private static async Task CheckDomain(string domain)
        {
            var url = String.Format("https://login.microsoftonline.com/common/UserRealm/?user={0}&api-version=1.0&checkForMicrosoftAccount=false&fallback_domain={1}", domain, domain);

            var httpClient = new HttpClient();

            var response = await httpClient.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine("Error. Status code: {0}. Body:", response.StatusCode);
                Console.WriteLine(content);
                Environment.Exit(1);
            }

            Console.WriteLine(content);
            Console.WriteLine("Domain exist and active");
        }

        /// <summary>
        /// Obtains client P2P certificates ans saves them into the corresponding files.
        /// </summary>
        /// <param name="user">Account credentials</param>
        /// <param name="tenantId">Tenant id</param>
        /// <param name="device">Device credentials (private key and certificate)</param>
        /// <returns></returns>
        public static async Task ObtainClientP2PCertificate(UserCreds user, string tenantId, DeviceCreds device)
        {
            Console.WriteLine("Start obtaining client P2P certificates...");

            await CheckDomain(user.Domain);

            var nonce = await RequestNonce(tenantId);
            Console.WriteLine("First nonce: {0}", nonce);

            var response = await TokenWithTgt(user, tenantId, nonce, device);

            var responseJson = JsonDocument.Parse(response);
            var refreshToken = responseJson.RootElement.GetProperty("refresh_token").ToString();
            var sessionKeyJwe = responseJson.RootElement.GetProperty("session_key_jwe").ToString();
            var sessionKey = CryptoUtils.DecryptSessionKeyFromJwe(sessionKeyJwe, device.Key);

            nonce = await RequestNonce(tenantId);
            Console.WriteLine("Second nonce: {0}", nonce);

            // randomly generated nonce
            // we can hard code it for our tool
            byte[] context = { 25, 152, 185, 126, 55, 118, 199, 221, 254, 108, 255, 202, 88, 128, 76, 218, 200, 157, 211, 63, 242, 37, 152, 198 };
            var contextBase64 = "GZi5fjd2x93+bP/KWIBM2sid0z/yJZjG";

            var signingKey = CryptoUtils.DeriveSigningKey(sessionKey, context);

            var certificateJwe = await RdpCertificate(
                nonce,
                contextBase64,
                tenantId,
                refreshToken,
                signingKey,
                user,
                device
            );

            var certificates = CryptoUtils.DecryptCeritficate(sessionKey, CryptoUtils.ExtractContextFromJwe(certificateJwe), certificateJwe);
            var id = string.Format("{0}_client_auth", device.Id);

            Console.WriteLine(
                "The client P2P certificate (.cer) has been written into the file: {0}",
                CryptoUtils.PemCrtToFile(certificates[0], id + "_p2p")
            );

            Console.WriteLine(
                "The client P2P CA certificate (.cer) has been written into the file: {0}",
                CryptoUtils.PemCrtToFile(certificates[1], id + "_p2p_ca")
            );

            Console.WriteLine("Finished obtaining client P2P certificates!");
        }

        private static async Task<string> RdpCertificate(
            string nonce,
            string context,
            string tenantId,
            string refreshToken,
            byte[] signingKey,
            UserCreds user,
            DeviceCreds device
        )
        {
            Console.WriteLine("Start RDP certificate obtaining...");

            var httpClient = new HttpClient();

            var url = string.Format("https://login.microsoftonline.com/{0}/oauth2/token", tenantId);

            var certForm = new Dictionary<string, string>();
            certForm.Add("request", JwtUtils.GenerateRdpCertificateRequestJwt(
                nonce,
                context,
                user.Username,
                refreshToken,
                signingKey,
                device.Key
            ));
            certForm.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            certForm.Add("windows_api_version", "2.2");

            var response = await httpClient.PostAsync(url, new FormUrlEncodedContent(certForm));
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", response.StatusCode));
                Console.WriteLine(content);

                Environment.Exit(1);
            }

            Console.WriteLine(content);
            return content;
        }

        /// <summary>
        /// Obtains P2P certificate for server autherization using device key and certificate. Saves certificates in the 
        /// corresponding files:
        /// * `{device_id}_server_auth_p2p.cer`
        /// * `{device_id}_server_auth_p2p_ca.cer`
        /// </summary>
        /// <param name="domain">AzureAD domain</param>
        /// <param name="tenantId">Tenant id</param>
        /// <param name="device">Device credentials</param>
        /// <returns></returns>
        public static async Task ObtainServerP2PCertificate(string domain, string tenantId, DeviceCreds device)
        {
            Console.WriteLine("Start obtaining server P2P certificates...");

            var url = string.Format("https://login.microsoftonline.com/{0}/oauth2/token", tenantId);

            var nonce = await RequestNonce(tenantId);

            var certForm = new Dictionary<string, string>();
            certForm.Add("request", JwtUtils.GenerateP2PRequestJwt(
                nonce,
                device,
                string.Format("tenjo.{0}", domain)
            ));
            certForm.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            certForm.Add("windows_api_version", "2.0");

            var httpClient = new HttpClient();

            var response = await httpClient.PostAsync(url, new FormUrlEncodedContent(certForm));
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", response.StatusCode));
                Console.WriteLine(content);

                Environment.Exit(1);
            }

            Console.WriteLine(content);
            var p2pCerificatesResponse = P2PCertificatesResponse.FromString(content);
            var id = string.Format("{0}_server_auth", device.Id);

            Console.WriteLine(
                "The server P2P certificate (.cer) has been written into the file: {0}",
                CryptoUtils.PemCrtToFile(p2pCerificatesResponse.x5c, id + "_p2p")
            );

            Console.WriteLine(
                "The server P2P CA certificate (.cer) has been written into the file: {0}",
                CryptoUtils.PemCrtToFile(p2pCerificatesResponse.x5c_ca, id + "_p2p_ca")
            );

            Console.WriteLine("Finished obtaining server P2P certificates!");
        }

        /// <summary>
        /// Obtains P2P certificates.
        /// </summary>
        /// <param name="deviceId">Device id</param>
        /// <param name="domain">Azure AD domain</param>
        /// <param name="tenantId">Azure AD tenant id</param>
        /// <param name="device">Device credentials (private key and certificate)</param>
        /// <returns></returns>
        public static async Task ObtainP2PCertificates(string deviceId, string domain, string tenantId, DeviceCreds device)
        {
            Console.WriteLine("Start obtaining device P2P certificates...");

            var httpClient = new HttpClient();

            var url = string.Format("https://login.microsoftonline.com/{0}/oauth2/token", tenantId);

            var nonceForm = new Dictionary<string, string>();
            nonceForm.Add("grant_type", "srv_challenge");

            var nonceResponse = await httpClient.PostAsync(url, new FormUrlEncodedContent(nonceForm));
            var nonceContent = await nonceResponse.Content.ReadAsStringAsync();

            if (nonceResponse.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", nonceResponse.StatusCode));
                Console.WriteLine(nonceContent);
                Environment.Exit(1);
            }

            Console.WriteLine(nonceContent);

            var document = JsonDocument.Parse(nonceContent);
            var nonce = document.RootElement.GetProperty("Nonce");

            var certForm = new Dictionary<string, string>();
            certForm.Add("request", JwtUtils.GenerateP2PRequestJwt(
                nonce.ToString(),
                device,
                string.Format("mypc.{0}", domain)
            ));
            certForm.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            certForm.Add("windows_api_version", "2.0");

            var response = await httpClient.PostAsync(url, new FormUrlEncodedContent(certForm));
            var content = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(string.Format("Error. Status code: {0}. Body:", response.StatusCode));
                Console.WriteLine(content);

                Environment.Exit(1);
            }

            Console.WriteLine(content);
            var p2pCerificatesResponse = P2PCertificatesResponse.FromString(content);

            Console.WriteLine(
                "The device P2P certificate (.cer) has been written into the file: {0}",
                CryptoUtils.PemCrtToFile(p2pCerificatesResponse.x5c, deviceId + "_p2p")
            );

            Console.WriteLine(
                "The device P2P CA certificate (.cer) has been written into the file: {0}",
                CryptoUtils.PemCrtToFile(p2pCerificatesResponse.x5c_ca, deviceId + "_p2p_ca")
            );

            Console.WriteLine("Finished obtaining device P2P certificates!");
        }
    }
}
