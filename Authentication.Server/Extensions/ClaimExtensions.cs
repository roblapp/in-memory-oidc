namespace Authentication.Server.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Authentication;
    using System.Security.Claims;
    using IdentityModel;

    public static class ClaimExtensions
    {
        public static Claim GetSubjectClaim(this List<Claim> claims)
        {
            var subjectClaim = claims.SingleOrDefault(x => x.Type == JwtClaimTypes.Subject);

            // ReSharper disable once MergeSequentialChecks
            if (subjectClaim == null || string.IsNullOrWhiteSpace(subjectClaim.Value))
            {
                //TODO replace with a custom Exception
                throw new Exception("Missing subject claim");
            }

            return subjectClaim;
        }

        public static Claim GetEmailClaim(this List<Claim> claims)
        {
            var emailAddressClaim = claims.SingleOrDefault(x => x.Type == ClaimTypes.Email);
            // ReSharper disable once MergeSequentialChecks
            if (emailAddressClaim == null || string.IsNullOrWhiteSpace(emailAddressClaim.Value))
            {
                //TODO replace with a custom Exception
                throw new Exception("Missing email claim");
            }

            return emailAddressClaim;
        }

        public static Claim GetProviderIdClaim(this List<Claim> claims)
        {
            // try to determine the unique id of the external user - the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var providerIdentifierClaim = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Subject);

            // ReSharper disable once ConvertIfStatementToNullCoalescingExpression
            if (providerIdentifierClaim == null)
            {
                providerIdentifierClaim = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            }

            if (providerIdentifierClaim == null)
            {
                throw new AuthenticationException("Unknown userid");
            }

            return providerIdentifierClaim;
        }
    }
}
