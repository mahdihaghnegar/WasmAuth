# WasmAuth
Add Blazor wasm Authentication and Authorization
1-Create webassmbly blazor
2-server->appsettings.json: set name of db
3-view->other winows-> package manage console: update-database
4-in client 
4-1 add CustomUserFactory.cs class




using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication.Internal;

namespace WASM.Client
{
    public class CustomUserFactory : AccountClaimsPrincipalFactory<RemoteUserAccount>
    {
        public CustomUserFactory(IAccessTokenProviderAccessor accessor) : base(accessor)
        {
        }

        public async override ValueTask<ClaimsPrincipal> CreateUserAsync(
            RemoteUserAccount account,
            RemoteAuthenticationUserOptions options)
        {
            var user = await base.CreateUserAsync(account, options);

            if (user.Identity.IsAuthenticated)
            {
                var identity = (ClaimsIdentity)user.Identity;
                var roleClaims = identity.FindAll(identity.RoleClaimType).ToArray();

                if (roleClaims != null && roleClaims.Any())
                {
                    foreach (var existingClaim in roleClaims)
                    {
                        identity.RemoveClaim(existingClaim);
                    }

                    var rolesElem = account.AdditionalProperties[identity.RoleClaimType];

                    if (rolesElem is JsonElement roles)
                    {
                        if (roles.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var role in roles.EnumerateArray())
                            {
                                identity.AddClaim(new Claim(options.RoleClaim, role.GetString()));
                            }
                        }
                        else
                        {
                            identity.AddClaim(new Claim(options.RoleClaim, roles.GetString()));
                        }
                    }
                }
            }

            return user;
        }
    }


