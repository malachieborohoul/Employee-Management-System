using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.indRoImplementations;

public class UserAccountRepository(IOptions<JwtSecion> config, AppDbContext appDbContext):IUserAccount
{
    public async Task<GeneralResponse> CreateAsync(Register user)
    {
        if (user is null) return new GeneralResponse(false, "Model is empty ");
        var checkUser= await FindUserByEmail(user.Email!);
        if (checkUser != null) return new GeneralResponse(false, "User registered already");
        
        //Save user
        var applicationUser = await AddToDatabase(new ApplicationUser()
        {
            Fullname = user.Fullname,
            Email = user.Email,
            Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
        });
        
        //check, create and assign role
        var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));

        if (checkAdminRole is null)
        {
            var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
            await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
            return new GeneralResponse(true, "Account created!");
        }
        
        var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));

        if (checkUserRole is null)
        {
            var createUserRole = await AddToDatabase(new SystemRole() { Name = Constants.User });
            await AddToDatabase(new UserRole() { RoleId = createUserRole.Id, UserId = applicationUser.Id });
        }
        else
        {
            await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });

        }
        return new GeneralResponse(true, "Account created!");

    }

    public async Task<LoginResponse> SignInAsync(Login user)
    {
        if (user is null) return new LoginResponse(false, "Model is empty");

        var applicationUser = await FindUserByEmail(user.Email);

        if (applicationUser is null) return new LoginResponse(false, "User is not found");
        
        //Verify password
        if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
            return new LoginResponse(false, "Email/Password not valid");

        var getUserRole = await FindUserRole(applicationUser.Id);
        if (getUserRole is null) return new LoginResponse(false, "user not found");

        var getRoleName = await FindRoleName(getUserRole.RoleId);
        if (getRoleName is null) return new LoginResponse(false, "user not found");

        string jwtToken = GenerateToken(applicationUser, getRoleName!.Name);
        string refreshToken = GenerateRefreshToken();
        
        //Save the Refesh token to the database
        var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
        if (findUser is not null)
        {
            findUser!.Token = refreshToken;
            await appDbContext.SaveChangesAsync();

        }
        else
        {
            await AddToDatabase(new RefreshTokenInfo() { Token = refreshToken, UserId = applicationUser.Id });
        }
        
        return new LoginResponse(true, "Login successfully", jwtToken, refreshToken);

    }

    public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
    {
        if (token is null) return new LoginResponse(false, "Model is empty");

        var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token!.Equals(token.Token));
        if (findToken is null) return new LoginResponse(false, "Refresh token is required");
        
        //get user details
        var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Id.Equals(findToken.UserId));
        if (user is null) return new LoginResponse(false, "Refresh token could not be generatd because user not found");

        var userRole = await FindUserRole(user.Id);
        var roleName = await FindRoleName(user.Id);
        string jwtToken = GenerateToken(user, roleName.Name);
        string refreshToken = GenerateRefreshToken();
        var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == user.Id);
        if (updateRefreshToken is null)
            return new LoginResponse(false, "Refresh token could not be generated beacuse user has not signed in");
        updateRefreshToken.Token = refreshToken;
        await appDbContext.SaveChangesAsync();
        return new LoginResponse(true, "Token refreshed successfully", jwtToken, refreshToken);

    }
    private async Task<UserRole> FindUserRole(int userId ) =>
        await appDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId!.Equals(userId));
    
    private async Task<SystemRole> FindRoleName(int roleId ) =>
        await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id!.Equals(roleId));
    private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    private string GenerateToken(ApplicationUser user, string role)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var userClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Fullname!),
            new Claim(ClaimTypes.Email, user.Email!),
            new Claim(ClaimTypes.Role, role!),
        };
        var token = new JwtSecurityToken(
            issuer: config.Value.Issuer,
            audience: config.Value.Audience,
            claims: userClaims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials

        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<ApplicationUser> FindUserByEmail(string email) =>
        await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));

    private async Task<T> AddToDatabase<T>(T model)
    {
        var result = await appDbContext.AddAsync(model!);
        await appDbContext.SaveChangesAsync();
        return (T)result.Entity;

    }
}