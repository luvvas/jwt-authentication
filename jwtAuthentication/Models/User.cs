namespace jwtAuthentication.Models
{
  public class User
  {
    // Guess it needs to be Id instead userId
    public Guid UserId { get; set; }
    public string Username { get; set; }
    public byte[] PasswordHash { get; set; }
    public byte[] PasswordSalt { get; set; }

    public string RefeshToken { get; set; } = string.Empty;
    public DateTime TokenCreated { get; set; }
    public DateTime TokenExpires { get; set; }
  }
}
