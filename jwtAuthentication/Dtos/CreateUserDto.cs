using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace jwtAuthentication.Dtos
{
	public class CreateUserDto
	{
		public string Username { get; set; }
		public string Password { get; set; }
	}
}
