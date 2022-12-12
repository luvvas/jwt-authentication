using System.Security.Claims;

namespace jwtAuthentication.Services
{
  public class UserService : IUserService
  {
    private readonly IHttpContextAccessor _httpContextAccessor;
    public UserService(IHttpContextAccessor httpContextAccessor)
    {
      _httpContextAccessor = httpContextAccessor;
    }
    public object GetMyName()
    {
      object result = new { };
      if (_httpContextAccessor.HttpContext != null)
      {
        result = new
        {
          // Equals to User.FindFirstValue(ClaimTypes.Name) in the AuthController
          userName = _httpContextAccessor.HttpContext.User
            .FindFirstValue(ClaimTypes.Name),
          // Equals to User.FindFirstValue(ClaimTypes.Role) in the AuthController
          role = _httpContextAccessor.HttpContext.User
            .FindFirstValue(ClaimTypes.Role)
        };
      }

      return result;
    }
  }
}