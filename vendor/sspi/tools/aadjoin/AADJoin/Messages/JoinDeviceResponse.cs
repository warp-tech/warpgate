using System.Text.Json;
using System.Text.Json.Serialization;

namespace AADJoin.Messages
{
    public class JoinDeviceResponse
    {
        public class Cert
        {
            [JsonInclude]
            public string Thumbprint { get; set; }
            [JsonInclude]
            public string RawBody { get; set; }
        }

        public class Usr
        {
            [JsonInclude]
            public string Upn { get; set; }
        }

        public class MembershipChgs
        {
            [JsonInclude]
            public string LocalSID { get; set; }
            [JsonInclude]
            public string[] AddSIDs { get; set; }
        }

        public Cert Certificate { get; set; }
        public Usr User { get; set; }
        public MembershipChgs[] MembershipChanges { get; set; }

        public static JoinDeviceResponse FromString(string data)
        {
            return JsonSerializer.Deserialize<JoinDeviceResponse>(data);
        }
    }
}
