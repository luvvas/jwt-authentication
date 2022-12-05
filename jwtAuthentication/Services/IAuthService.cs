using jwtAuthentication.Dtos;
using jwtAuthentication.Models;

namespace jwtAuthentication.Services
{
	public interface IAuthService
	{
		Task<ServiceResponse<List<User>>> registerUser(GetUserDto request);
		Task<ServiceResponse<User>> loginUser(GetUserDto request);
		Task<ServiceResponse<List<User>>> getAllUsers();
		Task<ServiceResponse<User>> getUserByUsername(string username);
		Task<ServiceResponse<User>> updateUser(User request);
		Task<ServiceResponse<List<User>>> deleteUser(string username);
	}
}
