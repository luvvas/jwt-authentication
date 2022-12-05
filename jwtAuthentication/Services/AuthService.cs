using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using jwtAuthentication.Data;
using jwtAuthentication.Dtos;
using jwtAuthentication.Models;

namespace jwtAuthentication.Services
{
	public class AuthService : IAuthService
	{
		private readonly IConfiguration configuration;
		private readonly DataContext context;
		public AuthService(IConfiguration configuration, DataContext context) {
			this.configuration = configuration;
			this.context = context;
		}

		public async Task<ServiceResponse<List<User>>> registerUser(UserDto request)
		{
			var serviceResponse = new ServiceResponse<List<User>>();

			try
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

				serviceResponse.Data = await context.Users.ToListAsync();

			} catch (Exception ex)
			{
				serviceResponse.Success = false;
				serviceResponse.Message = ex.Message;
			}

			return (serviceResponse);
		}
		public async Task<ServiceResponse<User>> loginUser(UserDto request)
		{
			var serviceResponse = new ServiceResponse<User>();

			try
			{
				var dbUser = await context.Users
					.Where(u => u.Username.Equals(request.Username))
					.FirstOrDefaultAsync();

				if (dbUser != null)
				{
					if (VerifyPasswordHash(request.Password, dbUser.PasswordHash, dbUser.PasswordSalt))
					{
						serviceResponse.Data = dbUser;
						var token = CreateToken(dbUser);
					} else
					{
						serviceResponse.Success = false;
						serviceResponse.Message = "Wrong password.";
					}
					
				} else
				{
					serviceResponse.Success = false;
					serviceResponse.Message = "User not found.";
				}
			} catch (Exception ex)
			{
				serviceResponse.Success = false;
				serviceResponse.Message = ex.Message;
			}

			return serviceResponse;
		}

		public async Task<ServiceResponse<List<User>>> getAllUsers()
		{
			var serviceResponse = new ServiceResponse<List<User>>();

			try
			{
				serviceResponse.Data = await context.Users.ToListAsync();
			} catch (Exception ex)
			{
				serviceResponse.Success = false;
				serviceResponse.Message = ex.Message;
			}

			return serviceResponse;
		}

		public async Task<ServiceResponse<User>> getUserByUsername(string username)
		{
			var serviceResponse = new ServiceResponse<User>();

			try
			{
				var dbUser = await context.Users
					.FirstOrDefaultAsync(u => u.Username.Equals(username));

				if (dbUser == null)
				{
					return null;
				}

				serviceResponse.Data = dbUser;
			} catch (Exception ex)
			{
				serviceResponse.Success = false;
				serviceResponse.Message = ex.Message;
			}

			return serviceResponse;
		}
		public async Task<ServiceResponse<User>> getUserByUserId(Guid userId)
		{
			var serviceResponse = new ServiceResponse<User>();

			try
			{
				var dbUser = await context.Users
					.FindAsync(userId);

				if (dbUser == null)
				{
					return null;
				}

				serviceResponse.Data = dbUser;
			} catch (Exception ex)
			{
				serviceResponse.Success = false;
				serviceResponse.Message = ex.Message;
			}


			return serviceResponse;
		}
		public async Task<ServiceResponse<User>> updateUser(User request)
		{
			var serviceResponse = new ServiceResponse<User>();

			try
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
			
				serviceResponse.Data = dbUser;
			} catch (Exception ex)
			{
				serviceResponse.Success = false;
				serviceResponse.Message = ex.Message;
			}
 

			return serviceResponse;
		}
		public async Task<ServiceResponse<List<User>>> deleteUser(string username)
		{
			var serviceResponse = new ServiceResponse<List<User>>();

			var dbUser = await context.Users
				.FirstOrDefaultAsync(u => u.Username.Equals(username));

			if (dbUser == null)
			{
				return null;
			}

			context.Users.Remove(dbUser);
			await this.context.SaveChangesAsync();

			serviceResponse.Data = await this.context.Users.ToListAsync();

			return serviceResponse;
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
