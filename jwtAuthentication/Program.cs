global using Microsoft.EntityFrameworkCore;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

using jwtAuthentication.Data;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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
