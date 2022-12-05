using jwtAuthentication.Dtos;
using jwtAuthentication.Models;

namespace jwtAuthentication.Services
{
	public interface IAuthService
	{
		Task<ServiceResponse<List<GetUserDto>>> registerUser(CreateUserDto request);
		Task<ServiceResponse<GetUserDto>> loginUser(CreateUserDto request);
		Task<ServiceResponse<List<GetUserDto>>> getAllUsers();
		Task<ServiceResponse<GetUserDto>> getUserByUsername(string username);
		Task<ServiceResponse<GetUserDto>> updateUser(UpdateUserDto request);
		Task<ServiceResponse<List<GetUserDto>>> deleteUser(string username);
	}
}
