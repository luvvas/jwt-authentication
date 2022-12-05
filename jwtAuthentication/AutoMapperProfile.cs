using AutoMapper;

using jwtAuthentication.Dtos;
using jwtAuthentication.Models;

namespace jwtAuthentication
{
	public class AutoMapperProfile : Profile
	{
		public AutoMapperProfile() 
		{
			CreateMap<User, GetUserDto>();
		}
	}
}
