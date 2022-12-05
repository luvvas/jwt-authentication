using jwtAuthentication.Data;
using jwtAuthentication.Dtos;
using jwtAuthentication.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace jwtAuthentication.Services
{
	public class AuthService : IAuthService
	{
		private readonly IConfiguration configuration;
		private readonly DataContext context;
		public AuthService(IConfiguration configuration, DataContext context) {
			this.context = context;
		}

		public async Task<User> registerUser(UserDto request)
		{
			// passwordHash e passwordSalt atualizam por referência quando CreatePasswordHash() é executado
			CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

			var newUser = new User
			{
				Username = request.Username,
				PasswordHash = passwordHash,
				PasswordSalt = passwordSalt
			};

			context.Users.Add(newUser);
			await context.SaveChangesAsync();

			return (newUser);
		}
		public async Task<string> loginUser(UserDto request)
		{
			var dbUser = await context.Users
				.Where(u => u.Username.Contains(request.Username))
				.FirstOrDefaultAsync();

			if (dbUser == null)
			{
				return null;
			}

			if (!VerifyPasswordHash(request.Password, dbUser.PasswordHash, dbUser.PasswordSalt))
			{
				return null;
			}

			string token = CreateToken(dbUser);
			return token;
		}
		public async Task<List<User>> getAllUsers()
		{
			return await context.Users.ToListAsync();
		}
		public async Task<User> getUserByUsername(string username)
		{
			var dbUser = await context.Users
				.FirstOrDefaultAsync(u => u.Username.Equals(username));

			if (dbUser == null)
			{
				return null;
			}

			return dbUser;
		}
		public async Task<User> getUserByUserId(Guid userId)
		{
			var dbUser = await context.Users
				.FindAsync(userId);

			if (dbUser == null)
			{
				return null;
			}

			return dbUser;
		}
		public async Task<User> updateUser(User request)
		{
			var dbUser = await context.Users.FindAsync(request.UserId);

			if (dbUser != null)
			{
				dbUser.Username = request.Username;

				await context.SaveChangesAsync();
			}
			else
			{
				return null;
			}

			return dbUser;
		}
		public async Task<List<User>> deleteUser(string username)
		{
			var dbUser = await context.Users
				.FirstOrDefaultAsync(u => u.Username.Equals(username));

			if (dbUser == null)
			{
				return null;
			}

			context.Users.Remove(dbUser);
			await this.context.SaveChangesAsync();

			return await this.context.Users.ToListAsync();
		}

		private string CreateToken(User user)
		{
			List<Claim> claims = new List<Claim>
			{
				new Claim(ClaimTypes.Name, user.Username)
			};

			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
				configuration.GetSection("AppSettings:Token").Value));

			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

			var token = new JwtSecurityToken(
				claims: claims,
				expires: DateTime.Now.AddDays(1),
				signingCredentials: creds
			);

			var jwt = new JwtSecurityTokenHandler().WriteToken(token);

			return jwt;
		}

		private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
		{
			using (var hmac = new HMACSHA512())
			{
				passwordSalt = hmac.Key;
				passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
			}
		}

		private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
		{
			using (var hmac = new HMACSHA512(passwordSalt))
			{
				var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

				return computedHash.SequenceEqual(passwordHash);
			}
		}
	}
}
