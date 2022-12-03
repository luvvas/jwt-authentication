using jwtAuthentication.Dtos;
using jwtAuthentication.Models;
using Microsoft.AspNetCore.Mvc;

using System.Security.Cryptography;
using System.Text;

namespace jwtAuthentication.Controllers
{
	public class AuthController : ControllerBase
	{
		public static User user = new User();

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

			return Ok("Deu certo.");
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
