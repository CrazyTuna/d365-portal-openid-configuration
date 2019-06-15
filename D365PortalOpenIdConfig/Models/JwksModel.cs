using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace D365PortalOpenIdConfig.Models
{
    public class JwksModel
    {
        [JsonProperty("keys")]
        public ICollection<JwksKeyModel> Keys { get; set; }
    }

    public class JwksKeyModel
    {
        [JsonProperty("use")]
        public string Use { get; set; } = "sig";

        [JsonProperty("kty")]
        public string Kty { get; set; } = "RSA";

        [JsonProperty("n")]
        public string N { get; set; }

        [JsonProperty("e")]
        public string E { get; set; }
    }
}
