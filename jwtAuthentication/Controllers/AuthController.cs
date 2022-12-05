using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using jwtAuthentication.Data;
using jwtAuthentication.Models;
using jwtAuthentication.Dtos;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace jwtAuthentication.Controllers
{
	public class AuthController : ControllerBase
	{
		//public static User user = new User();

		private readonly IConfiguration configuration;
		private readonly DataContext context;
		public AuthController(IConfiguration configuration, DataContext context)
		{
			this.configuration = configuration;
			this.context = context;
		}

		[HttpPost("registerUser")]
		public async Task<ActionResult<User>> registerUser([FromBody] UserDto request)
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

			return Ok(await context.Users.ToListAsync());
		}

		[HttpPost("loginUser")]
		public async Task<ActionResult<string>> loginUser([FromBody] UserDto request)
		{
			var dbUser = await context.Users
				.Where(u => u.Username.Contains(request.Username))
				.FirstOrDefaultAsync();

			if(dbUser == null)
			{
				return BadRequest("User not found.");
			}

			if (!VerifyPasswordHash(request.Password, dbUser.PasswordHash, dbUser.PasswordSalt))
			{
				return BadRequest("Wrong password.");
			}

			string token = CreateToken(dbUser);
			return Ok(token);
		}

		[HttpGet("getAllUsers")]
		public async Task<ActionResult<List<User>>> getAllUsers()
		{
			return Ok(await context.Users.ToListAsync());
		}

		[HttpGet("getUserByUsername/{username}")]
		public async Task<ActionResult<User>> getUserByUsername([FromRoute] string username)
		{
			var dbUser = await context.Users
				.FirstOrDefaultAsync(u => u.Username.Equals(username));

			if(dbUser == null)
			{
				return BadRequest("User not found");
			}

			return Ok(dbUser);
		}

		[HttpGet("getUserByUserId/{userId}")]
		public async Task<ActionResult<User>> getUserByUserId([FromRoute] Guid userId)
		{
			var dbUser = await context.Users
				.FindAsync(userId);

			if(dbUser == null)
			{
				return BadRequest("User not found");
			}

			return Ok(dbUser);
		}

		// Need to change password
		[HttpPut("updateUser")]
		public async Task<ActionResult<User>> updateUser([FromBody] User request)
		{
			var dbUser = await context.Users.FindAsync(request.UserId);

			if(dbUser != null)
			{
				dbUser.Username = request.Username;

				await context.SaveChangesAsync();
			} else { 
				return BadRequest("User not found");
			}

			return Ok(dbUser);
		}

		[HttpDelete("deleteUser/{username}")]
		public async Task<ActionResult<List<User>>> deleteUser([FromRoute] string username)
		{
			var dbUser = await context.Users
				.FirstOrDefaultAsync(u => u.Username.Equals(username));

			if (dbUser == null)
			{
				return BadRequest("User not found");
			}

			context.Users.Remove(dbUser);
			await this.context.SaveChangesAsync();

			return Ok(await this.context.Users.ToListAsync());
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
			using(var hmac = new HMACSHA512(passwordSalt))
			{
				var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

				return computedHash.SequenceEqual(passwordHash);
			}
		}
	}
}
