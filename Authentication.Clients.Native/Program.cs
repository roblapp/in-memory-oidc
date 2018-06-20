namespace Authentication.Clients.Native
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using IdentityModel.Client;

    public class Program
    {
        public static void Main(string[] args)
        {
            RunAsync().GetAwaiter().GetResult();

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        public static async Task RunAsync()
        {
            var tokenClient = new TokenClient("http://localhost:5000/connect/token");
            await tokenClient.RequestCustomAsync(
                new Dictionary<string, string>
                {
                    { "", ""},
                    { "", ""},
                    { "", ""},
                    { "", ""},
                    { "", ""}
                });
        }
    }
}
