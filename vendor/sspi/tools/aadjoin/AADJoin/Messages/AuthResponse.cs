using System;
using System.Text.Json;

namespace AADJoin.Messages
{
    public class AuthResponse
    {
        public string token_type { get; set; }
        public string scope { get; set; }
        public string expires_in { get; set; }
        public string ext_expires_in { get; set; }
        public string expires_on { get; set; }
        public string not_before { get; set; }
        public string resource { get; set; }
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public string id_token { get; set; }

        public static AuthResponse fromString(string authResponse)
        {
            return JsonSerializer.Deserialize<AuthResponse>(authResponse);
        }

        public string GetTenantId()
        {
            var payload = id_token.Split('.')[1];
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }

            var document = JsonDocument.Parse(Convert.FromBase64String(payload));
            var idToken = document.RootElement.GetProperty("tid");

            return idToken.GetString();
        }
    }
}
