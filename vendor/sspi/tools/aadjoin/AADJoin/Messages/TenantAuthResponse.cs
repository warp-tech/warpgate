using System;
using System.Text.Json;

namespace AADJoin.Messages
{
    public class TenantAuthResponse
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

        public static TenantAuthResponse FromString(string authResponse)
        {
            return JsonSerializer.Deserialize<TenantAuthResponse>(authResponse);
        }
    }
}
