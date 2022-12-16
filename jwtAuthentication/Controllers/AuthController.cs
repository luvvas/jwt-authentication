using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using jwtAuthentication.Data;
using jwtAuthentication.Models;
using jwtAuthentication.Dtos;

namespace jwtAuthentication.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
    private static readonly string[] Summaries = new[]
    {
      "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };
    private readonly IConfiguration _configuration;
    private readonly DataContext _context;
    private readonly IUserService _userService;
    public AuthController(IConfiguration configuration, DataContext context, IUserService userService)
    {
      _configuration = configuration;
      _context = context;
      _userService = userService;
    }

    [HttpGet("getMe"), Authorize]
    public ActionResult<object> GetMe()
    {
      var userName = _userService.GetMyName();

      return Ok(userName);

      // var userName = User?.Identity?.Name;
      // or
      // var userName = User.FindFirstValue(ClaimTypes.Name);
      // var role = User.FindFirstValue(ClaimTypes.Role);

      // return Ok(new { userName, role });
    }

    [HttpPost("registerUser")]
    public async Task<ActionResult<User>> registerUser([FromBody] UserDto request)
    {
      CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

      var newUser = new User
      {
        Username = request.Username,
        PasswordHash = passwordHash,
        PasswordSalt = passwordSalt,
      };

      _context.Users.Add(newUser);
      await _context.SaveChangesAsync();

      return Ok(newUser);
    }

    [HttpPost("loginUser")]
    public async Task<ActionResult<string>> loginUser([FromBody] UserDto request)
    {
      var dbUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

      if (dbUser == null)
      {
        return BadRequest("User not found.");
      }

      if (!VerifyPasswordHash(request.Password, dbUser.PasswordHash, dbUser.PasswordSalt))
      {
        return BadRequest("Wrong password.");
      }

      string token = CreateToken(dbUser);

      var refreshToken = GenerateRefreshToken();
      await SetRefreshToken(refreshToken, dbUser);

      return Ok(token);
    }

    [HttpPost("refreshToken")]
    public async Task<ActionResult<string>> RefreshToken()
    {
      var refreshToken = Request.Cookies["refreshToken"];

      var dbUser = await _context.Users
        .FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

      if (dbUser == null)
      {
        return Unauthorized("Invalid Refresh Token.");
      }
      else if (dbUser.TokenExpires < DateTime.UtcNow)
      {
        return Unauthorized("Token expired.");
      }

      string token = CreateToken(dbUser);
      var newRefreshToken = GenerateRefreshToken();
      await SetRefreshToken(newRefreshToken, dbUser);

      return Ok(token);
    }

    [HttpGet("getWeatherForecast"), Authorize(Roles = "Admin")]
    public IEnumerable<WeatherForecast> Get()
    {
      return Enumerable.Range(1, 5).Select(index => new WeatherForecast
      {
        Date = DateTime.Now.AddDays(index),
        TemperatureC = Random.Shared.Next(-20, 55),
        Summary = Summaries[Random.Shared.Next(Summaries.Length)]
      })
      .ToArray();
    }

    private RefreshToken GenerateRefreshToken()
    {
      var refreshToken = new RefreshToken
      {
        Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
        Expires = DateTime.UtcNow.AddDays(7),
        Created = DateTime.UtcNow
      };

      return refreshToken;
    }

    private async Task SetRefreshToken(RefreshToken newRefreshToken, User dbUser)
    {
      var cookieOptions = new CookieOptions
      {
        HttpOnly = true,
        Expires = newRefreshToken.Expires
      };
      Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

      dbUser.RefreshToken = newRefreshToken.Token;
      dbUser.TokenCreated = newRefreshToken.Created;
      dbUser.TokenExpires = newRefreshToken.Expires;

      await _context.SaveChangesAsync();
    }

    // Need to review
    private string CreateToken(User user)
    {
      List<Claim> claims = new List<Claim>
      {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, "Noob")
      };

      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
        _configuration.GetSection("AppSettings:Token").Value));

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
