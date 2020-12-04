using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace AdalMsalTestProj
{
    class Config
    {

        public const string ClientId = "";
        public const string TenantId = "";

        // Only needed for Username / Password. IMPORTANT: do not post network traces of Username / Password flow on GitHub etc.
        public const string Username = "";
        public const string Password = "";

        // Use any scope / resource you want. It's recommended that you pre-consent to them in Azure Portal
        public const string MsalScope = "https://management.core.windows.net/.default";
        public const string AdalResource = "https://management.core.windows.net/";

        // only needed for interactive authentication. The URL must also be registered in Azure Portal / AAD / App Registration / Authentication
        public const string RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"; 

    }

    class Program
    {
        public static async Task Main(string[] args)
        {
            if (
                string.IsNullOrEmpty(Config.ClientId) ||
                string.IsNullOrEmpty(Config.TenantId))
            {
                throw new InvalidOperationException("Please configure this app first.");
            }
            while (true)
            {
                Console.Clear();
                Console.WriteLine(@"
                1. Username / Password flow with ADAL 3.19.2
                2. Username / Password flow with MSAL 4.23.0
                3. Integrated Windows Auth with ADAL 
                4. Integrated Windows Auth with MSAL
                5. Interactive with ADAL 
                6. Interactive with MSAL 
                ");

                char.TryParse(Console.ReadLine(), out var selection);
                try
                {
                    var msalPca = CreateMsalPca();
                    var adalContext = new AuthenticationContext($"https://login.microsoftonline.com/{Config.TenantId}");
                    adalContext.TokenCache.Clear();


                    switch (selection)
                    {
                        #region ADAL
                        case '1':
                            if (string.IsNullOrEmpty(Config.Username) ||
                                string.IsNullOrEmpty(Config.Password))
                            {
                                throw new InvalidOperationException("Please configure a username and a password first");
                            }

                            var userPasswordCredential = new UserPasswordCredential(Config.Username, Config.Password);
                            var result1 = await adalContext.AcquireTokenAsync(Config.AdalResource, Config.ClientId, userPasswordCredential);
                            Console.WriteLine("Success! Token for " + result1.UserInfo.DisplayableId);

                            break;

                        case '3':
                            var iwaCredential = new UserCredential();
                            var result3 = await adalContext.AcquireTokenAsync(Config.AdalResource, Config.ClientId, iwaCredential);
                            Console.WriteLine("Success! Token for " + result3.UserInfo.DisplayableId);
                            break;
                        case '5':
                            var result5 = await adalContext.AcquireTokenAsync(
                                Config.AdalResource,
                                Config.ClientId,
                                new Uri(Config.RedirectUri),
                                new PlatformParameters(PromptBehavior.SelectAccount));
                            Console.WriteLine("Success! Token for " + result5.UserInfo.DisplayableId);

                            break;

                        #endregion

                        #region MSAL
                        case '2':
                            if (string.IsNullOrEmpty(Config.Username) ||
                                string.IsNullOrEmpty(Config.Password))
                            {
                                throw new InvalidOperationException("Please configure a username and a password first");
                            }

                            SecureString secureString = new NetworkCredential("", Config.Password).SecurePassword;
                            var result2 = await msalPca.AcquireTokenByUsernamePassword(new[] { Config.MsalScope }, Config.Username, secureString)
                                .ExecuteAsync();
                            Console.WriteLine("Success! Token for " + result2.Account.Username);
                            break;
                        case '4':
                            var result4 = await msalPca.AcquireTokenByIntegratedWindowsAuth(new[] { Config.MsalScope }).ExecuteAsync();
                            Console.WriteLine("Success! Token for " + result4.Account.Username);
                            break;
                        case '6':
                            var result6 = await msalPca.AcquireTokenInteractive(new[] { Config.MsalScope }).ExecuteAsync();
                            Console.WriteLine("Success! Token for " + result6.Account.Username);
                            break;
                            #endregion
                    }

                    Console.WriteLine("Press any key to continue");
                    Console.ReadKey();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(ex);
                    Console.ResetColor();
                    Console.ReadKey();
                }
            }

        }

        private static IPublicClientApplication CreateMsalPca()
        {
            var pcab = PublicClientApplicationBuilder.Create(Config.ClientId)
                            .WithAuthority(AzureCloudInstance.AzurePublic, Config.TenantId);

            if (!string.IsNullOrEmpty(Config.RedirectUri))
            {
                pcab = pcab.WithRedirectUri(Config.RedirectUri);
            }

            var pca = pcab.Build();

            return pca;
        }


    }
}
