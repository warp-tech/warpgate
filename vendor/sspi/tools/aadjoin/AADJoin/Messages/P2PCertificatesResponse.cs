using System.Text.Json;

namespace AADJoin.Messages
{
    public class P2PCertificatesResponse
    {
        public string token_type { get; set; }
        public string expires_in { get; set; }
        public string ext_expires_in { get; set; }
        public string expires_on { get; set; }
        public string x5c { get; set; }
        public string cert_token_use { get; set; }
        public string x5c_ca { get; set; }
        public string resource { get; set; }

        public static P2PCertificatesResponse FromString(string data)
        {
            return JsonSerializer.Deserialize<P2PCertificatesResponse>(data);
        }
    }
}
