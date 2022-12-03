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

namespace jwtAuthentication.Controllers
{
	public class AuthController : ControllerBase
	{
		public static User user = new User();

		private readonly IConfiguration configuration;
		private readonly DataContext context;
		public AuthController(IConfiguration configuration, DataContext context)
		{
			this.configuration = configuration;
			this.context = context;
		}

		[HttpPost("register")]
		public async Task<ActionResult<User>> Register([FromBody] UserDto request)
		{
			// passwordHash e passwordSalt atualizam por referência quando CreatePasswordHash() é executado
			CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

			user.Username = request.Username;
			user.PasswordHash = passwordHash;
			user.PasswordSalt = passwordSalt;

			return Ok(user);
		}

		[HttpPost("login")]
		public async Task<ActionResult<string>> Login([FromBody] UserDto request)
		{
			if(user.Username != request.Username)
			{
				return BadRequest("User not found.");
			}
			if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
			{
				return BadRequest("Wrong password.");
			}

			string token = CreateToken(user);
			return Ok(token);
		}

		[HttpGet("getAllUsers")]
		public async Task<ActionResult<List<User>>> getAllUsers()
		{
			return Ok(await context.Users.ToListAsync());
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
