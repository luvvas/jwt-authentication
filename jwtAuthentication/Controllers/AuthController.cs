﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using jwtAuthentication.Data;
using jwtAuthentication.Models;
using jwtAuthentication.Dtos;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using jwtAuthentication.Services;

namespace jwtAuthentication.Controllers
{
	public class AuthController : ControllerBase
	{
		private readonly IAuthService authService;
		public AuthController(IAuthService authService)
		{
			this.authService = authService;
		}

		[HttpPost("registerUser")]
		public async Task<ActionResult<ServiceResponse<List<User>>>> registerUser([FromBody] UserDto request)
		{
			var response = await authService.registerUser(request);
			return Ok(response);
		}

		[HttpPost("loginUser")]
		public async Task<ActionResult<ServiceResponse<User>>> loginUser([FromBody] UserDto request)
		{
			var response = await authService.loginUser(request);
			if (response.Data == null)
			{
				return NotFound(response);
			}

			return Ok(response);
		}

		[HttpGet("getAllUsers")]
		public async Task<ActionResult<ServiceResponse<List<User>>>> getAllUsers()
		{
			var response = await authService.getAllUsers();
			return Ok(response);
		}

		[HttpGet("getUserByUsername/{username}")]
		public async Task<ActionResult<User>> getUserByUsername([FromRoute] string username)
		{
			var response = await authService.getUserByUsername(username);
			return Ok(response);
		}

		// Need to change password
		[HttpPut("updateUser")]
		public async Task<ActionResult<ServiceResponse<User>>> updateUser([FromBody] User request)
		{
			var response = await authService.updateUser(request);
			return Ok(response);
		}

		[HttpDelete("deleteUser/{username}")]
		public async Task<ActionResult<ServiceResponse<List<User>>>> deleteUser([FromRoute] string username)
		{
			var response = await authService.deleteUser(username);
			return Ok(response);
		}
	}
}
