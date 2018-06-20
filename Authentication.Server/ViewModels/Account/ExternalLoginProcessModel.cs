namespace Authentication.Server.ViewModels.Account
{
    
    public class ExternalLoginProcessModel
    {
        public bool Successful { get; set; }

        public bool IsWindowsAuth { get; set; }

        //public bool IsExternalProvider { get; set; }
    }

    public class LocalLoginProcessResult
    {
        public bool Successful { get; set; }

        public bool IsCredentialsValid { get; set; }
    }
}
