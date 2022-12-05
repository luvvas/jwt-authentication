using jwtAuthentication.Dtos;
using jwtAuthentication.Models;

namespace jwtAuthentication.Services
{
	public interface IAuthService
	{
		Task<User> registerUser(UserDto request);
		Task<string> loginUser(UserDto request);
		Task<List<User>> getAllUsers();
		Task<User> getUserByUsername(string username);
		Task<User> getUserByUserId(Guid userId);
		Task<User> updateUser(User request);
		Task<List<User>> deleteUser(string username);
	}
}
