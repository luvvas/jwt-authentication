namespace jwtAuthentication.Dtos
{
	public class GetUserDto
	{
		public string Username { get; set; } = string.Empty;
		public string Password { get; set; } = string.Empty;
	}
}