namespace Authentication.Server.Extensions
{
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;

    public static class JsonExtensions
    {
        public static string AsJson(this object obj, bool showNullValues = false)
        {
            if (obj == null)
            {
                return null;
            }

            return JsonConvert.SerializeObject(
                obj,
                new JsonSerializerSettings
                {
                    NullValueHandling = showNullValues ? NullValueHandling.Include : NullValueHandling.Ignore,
                    ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
                    // removes returning $id, $ref
                    PreserveReferencesHandling = PreserveReferencesHandling.None,
                    DateFormatHandling = DateFormatHandling.IsoDateFormat,
                    Formatting = Formatting.Indented,
                    ContractResolver = new CamelCasePropertyNamesContractResolver()
                });
        }
    }
}
