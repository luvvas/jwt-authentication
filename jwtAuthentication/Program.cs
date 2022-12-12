global using Microsoft.EntityFrameworkCore;
global using jwtAuthentication.Services;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

using jwtAuthentication.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSwaggerGen(options =>
{
  options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
  {
    Description = "Standard Authorization header using the Bearer scheme(\"bearer {token}\")",
    In = ParameterLocation.Header,
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey
  });

  options.OperationFilter<SecurityRequirementsOperationFilter>();
});

builder.Services.AddAuthentication(
  JwtBearerDefaults.AuthenticationScheme
).AddJwtBearer(options =>
{
  options.TokenValidationParameters = new TokenValidationParameters
  {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8
      .GetBytes(builder.Configuration.GetSection("Appsettings:Token").Value)),
    ValidateIssuer = false,
    ValidateAudience = false
  };
});

builder.Services
  .AddEntityFrameworkNpgsql()
  .AddDbContext<DataContext>(options =>
  {
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
  });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
  app.UseSwagger();
  app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
