namespace jwtAuthentication.Models
{
	public class User
	{
		// Add an id when start using database
		public string Username { get; set; }
		public byte[] PasswordHash { get; set; }
		public byte[] PasswordSalt { get; set; }
	}
}
