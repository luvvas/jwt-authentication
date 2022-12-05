namespace jwtAuthentication.Dtos
{
	public class UpdateUserDto
	{
		public Guid UserId { get; set; }
		public string Username { get; set; } = string.Empty;
		// Gerar novo passwordHash/passwordSalt?
		public string Password { get; set; } = string.Empty;
	}
}
